from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
NUM_RE = re.compile(r"^\d+$")
PATH_RE = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/\-{}]+")


@dataclass
class AttackGraphEdge:
    source: str
    target: str
    relation: str
    evidence: str
    weight: int = 1


@dataclass
class AttackGraph:
    nodes: Dict[str, Dict[str, Any]]
    edges: List[AttackGraphEdge] = field(default_factory=list)
    paths: List[List[str]] = field(default_factory=list)


def _normalize_path(path: str) -> str:
    parts = [segment for segment in path.split("/") if segment]
    normalized = []
    for segment in parts:
        if NUM_RE.match(segment) or UUID_RE.match(segment):
            normalized.append("{id}")
        else:
            normalized.append(segment)
    return "/" + "/".join(normalized)


def _match_endpoint_id(host: str, method: str, path: str, endpoints: dict) -> Optional[str]:
    normalized = _normalize_path(path or "/")
    for endpoint_id, endpoint in endpoints.items():
        if endpoint.host == host and endpoint.method == method and endpoint.path == normalized:
            return endpoint_id
    return None


def _match_get_endpoint_id(host: str, path: str, endpoints: dict) -> Optional[str]:
    normalized = _normalize_path(path or "/")
    for endpoint_id, endpoint in endpoints.items():
        if endpoint.host == host and endpoint.method == "GET" and endpoint.path == normalized:
            return endpoint_id
    return None


def _session_key(record: Any) -> str:
    auth = record.headers.get("Authorization", "")[:48]
    cookie = record.headers.get("Cookie", "")[:48]
    return auth + cookie or "anonymous"


def _extract_paths_from_json(data: Any, out: set[str], depth: int = 0) -> None:
    if depth > 5:
        return
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, str):
                for match in PATH_RE.findall(value):
                    out.add(match)
            elif isinstance(value, (dict, list)):
                _extract_paths_from_json(value, out, depth + 1)
    elif isinstance(data, list):
        for item in data[:20]:
            _extract_paths_from_json(item, out, depth + 1)


def _extract_linked_paths(body: Optional[bytes]) -> List[str]:
    if not body:
        return []
    paths: set[str] = set()
    try:
        payload = json.loads(body.decode("utf-8", errors="ignore"))
    except Exception:
        payload = None
    if payload is not None:
        _extract_paths_from_json(payload, paths)
    else:
        text = body.decode("utf-8", errors="ignore")[:20000]
        for match in PATH_RE.findall(text):
            paths.add(match)
    return sorted(paths)


def build_attack_graph(records: list, endpoints: dict, max_depth: int = 4) -> AttackGraph:
    nodes = {
        endpoint_id: {
            "id": endpoint_id,
            "method": endpoint.method,
            "path": endpoint.path,
            "host": endpoint.host,
            "authRequired": endpoint.auth_required,
            "fuzzCases": endpoint.fuzz_cases,
        }
        for endpoint_id, endpoint in endpoints.items()
    }
    edge_map: Dict[Tuple[str, str, str], AttackGraphEdge] = {}

    sessions: Dict[Tuple[str, str], List[Tuple[int, Any]]] = {}
    for index, record in enumerate(records):
        parsed = urlparse(record.url)
        sessions.setdefault((parsed.netloc, _session_key(record)), []).append((index, record))

    for (host, _session), session_records in sessions.items():
        session_records.sort(key=lambda item: item[0])
        previous_endpoint_id: Optional[str] = None
        for _, record in session_records:
            parsed = urlparse(record.url)
            endpoint_id = _match_endpoint_id(parsed.netloc, record.method, parsed.path or "/", endpoints)
            if not endpoint_id:
                continue
            if previous_endpoint_id and previous_endpoint_id != endpoint_id:
                key = (previous_endpoint_id, endpoint_id, "sequence")
                if key not in edge_map:
                    edge_map[key] = AttackGraphEdge(
                        source=previous_endpoint_id,
                        target=endpoint_id,
                        relation="sequence",
                        evidence=f"Observed sequential request flow on {host}",
                    )
                else:
                    edge_map[key].weight += 1
            previous_endpoint_id = endpoint_id

            for linked_path in _extract_linked_paths(record.response_body):
                target_id = _match_get_endpoint_id(parsed.netloc, linked_path, endpoints)
                if target_id and target_id != endpoint_id:
                    key = (endpoint_id, target_id, "response_link")
                    if key not in edge_map:
                        edge_map[key] = AttackGraphEdge(
                            source=endpoint_id,
                            target=target_id,
                            relation="response_link",
                            evidence=f"Response body linked to {linked_path}",
                        )
                    else:
                        edge_map[key].weight += 1

    graph = AttackGraph(nodes=nodes, edges=list(edge_map.values()))
    graph.paths = enumerate_attack_paths(graph, max_depth=max_depth)
    return graph


def enumerate_attack_paths(graph: AttackGraph, max_depth: int = 4) -> List[List[str]]:
    adjacency: Dict[str, List[str]] = {}
    for edge in graph.edges:
        adjacency.setdefault(edge.source, []).append(edge.target)

    paths: List[List[str]] = []
    seen_paths: set[Tuple[str, ...]] = set()

    def _walk(path: List[str]) -> None:
        current = path[-1]
        next_nodes = adjacency.get(current, [])
        extended = False
        for next_node in next_nodes:
            if next_node in path or len(path) >= max_depth:
                continue
            extended = True
            _walk(path + [next_node])
        if len(path) >= 2 and (not extended or len(path) >= max_depth):
            key = tuple(path)
            if key not in seen_paths:
                seen_paths.add(key)
                paths.append(path)

    for node_id in graph.nodes.keys():
        _walk([node_id])

    return paths


def build_graph_chains(records: list, endpoints: dict, max_depth: int = 4) -> List[Any]:
    try:
        from backend.modules.stateful_fuzzer import ChainStep, RequestChain
    except ImportError:
        from modules.stateful_fuzzer import ChainStep, RequestChain

    graph = build_attack_graph(records, endpoints, max_depth=max_depth)
    representative_records: Dict[str, Any] = {}
    for record in records:
        parsed = urlparse(record.url)
        endpoint_id = _match_endpoint_id(parsed.netloc, record.method, parsed.path or "/", endpoints)
        if endpoint_id and endpoint_id not in representative_records:
            representative_records[endpoint_id] = record

    chains = []
    for path in graph.paths:
        if len(path) < 2:
            continue
        steps = []
        for order, endpoint_id in enumerate(path):
            endpoint = endpoints.get(endpoint_id)
            record = representative_records.get(endpoint_id)
            if not endpoint or record is None:
                steps = []
                break
            steps.append(
                ChainStep(
                    method=record.method,
                    path=urlparse(record.url).path or endpoint.path,
                    host=endpoint.host,
                    url=record.url,
                    headers=dict(record.headers),
                    body=record.body,
                    endpoint_id=endpoint_id,
                    order=order,
                )
            )
        if len(steps) >= 2:
            chains.append(
                RequestChain(
                    chain_id=f"graph-{uuid.uuid4().hex[:8]}",
                    steps=steps,
                    description="Attack graph path: " + " -> ".join(
                        f"{step.method} {step.path}" for step in steps
                    ),
                )
            )
    return chains

