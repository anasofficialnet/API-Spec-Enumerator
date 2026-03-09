"""
AASE Module 5: Shadow API Differential Analysis
================================================
Compares captured API traffic against an OpenAPI/Swagger spec
to find undocumented "shadow" endpoints and parameter mismatches.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class SpecEndpoint:
    """An endpoint parsed from an OpenAPI/Swagger spec."""
    method: str
    path: str
    summary: str = ""
    parameters: List[str] = field(default_factory=list)
    request_body_fields: List[str] = field(default_factory=list)
    deprecated: bool = False


@dataclass
class ShadowApiReport:
    """Result of comparing traffic vs spec."""
    # Endpoints in traffic but NOT in spec — undocumented "shadow" APIs
    undocumented: List[Dict[str, Any]] = field(default_factory=list)
    # Endpoints in spec but NOT in traffic — possibly unimplemented or untested
    unimplemented: List[Dict[str, Any]] = field(default_factory=list)
    # Endpoints in both but with parameter differences
    param_mismatches: List[Dict[str, Any]] = field(default_factory=list)
    # Summary stats
    total_spec_endpoints: int = 0
    total_traffic_endpoints: int = 0
    coverage_percent: float = 0.0


def _normalize_openapi_path(path: str) -> str:
    """Normalize OpenAPI path parameters to {id} for comparison."""
    # Convert {userId}, {item_id}, etc. to {id}
    return re.sub(r"\{[^}]+\}", "{id}", path)


def parse_openapi_spec(content: bytes, fmt: str = "json") -> List[SpecEndpoint]:
    """
    Parse an OpenAPI 2.0 (Swagger) or 3.x spec.
    Supports JSON and YAML formats.
    """
    if fmt == "yaml":
        try:
            import yaml
            data = yaml.safe_load(content.decode("utf-8", errors="ignore"))
        except ImportError:
            raise ValueError("PyYAML is required for YAML spec parsing. Install with: pip install pyyaml")
        except Exception as e:
            raise ValueError(f"Failed to parse YAML spec: {e}")
    else:
        try:
            data = json.loads(content.decode("utf-8", errors="ignore"))
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON spec: {e}")

    if not isinstance(data, dict):
        raise ValueError("Spec root must be a JSON object")

    endpoints: List[SpecEndpoint] = []

    # Detect OpenAPI version
    is_v3 = "openapi" in data  # OpenAPI 3.x
    paths = data.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            if method not in path_item:
                continue

            operation = path_item[method]
            if not isinstance(operation, dict):
                continue

            # Extract parameters
            params = []
            for param in operation.get("parameters", []) + path_item.get("parameters", []):
                if isinstance(param, dict):
                    params.append(param.get("name", ""))

            # Extract request body fields (OpenAPI 3.x)
            body_fields = []
            if is_v3:
                request_body = operation.get("requestBody", {})
                if isinstance(request_body, dict):
                    content = request_body.get("content", {})
                    for media_type, media_obj in content.items():
                        if isinstance(media_obj, dict):
                            schema = media_obj.get("schema", {})
                            body_fields.extend(_extract_schema_fields(schema, data))
            else:
                # Swagger 2.0: body params
                for param in operation.get("parameters", []):
                    if isinstance(param, dict) and param.get("in") == "body":
                        schema = param.get("schema", {})
                        body_fields.extend(_extract_schema_fields(schema, data))

            endpoints.append(SpecEndpoint(
                method=method.upper(),
                path=path,
                summary=operation.get("summary", operation.get("description", ""))[:200],
                parameters=[p for p in params if p],
                request_body_fields=body_fields,
                deprecated=operation.get("deprecated", False),
            ))

    return endpoints


def _extract_schema_fields(schema: dict, root_spec: dict, depth: int = 0) -> List[str]:
    """Extract field names from a JSON Schema object."""
    if depth > 5 or not isinstance(schema, dict):
        return []

    # Handle $ref
    ref = schema.get("$ref")
    if ref and isinstance(ref, str):
        schema = _resolve_ref(ref, root_spec)
        if not schema:
            return []

    fields = []
    properties = schema.get("properties", {})
    if isinstance(properties, dict):
        fields.extend(properties.keys())
        for prop_name, prop_schema in properties.items():
            if isinstance(prop_schema, dict) and prop_schema.get("type") == "object":
                sub_fields = _extract_schema_fields(prop_schema, root_spec, depth + 1)
                fields.extend(f"{prop_name}.{sf}" for sf in sub_fields)

    # Handle allOf/oneOf/anyOf
    for combiner in ("allOf", "oneOf", "anyOf"):
        combo = schema.get(combiner, [])
        if isinstance(combo, list):
            for sub_schema in combo:
                fields.extend(_extract_schema_fields(sub_schema, root_spec, depth + 1))

    return fields


def _resolve_ref(ref: str, root_spec: dict) -> Optional[dict]:
    """Resolve a $ref pointer like '#/definitions/User' or '#/components/schemas/User'."""
    if not ref.startswith("#/"):
        return None
    parts = ref[2:].split("/")
    node = root_spec
    for part in parts:
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node if isinstance(node, dict) else None


def diff_traffic_vs_spec(
    traffic_endpoints: dict,
    spec_endpoints: List[SpecEndpoint],
) -> ShadowApiReport:
    """
    Compare discovered traffic endpoints against the OpenAPI spec.
    Returns a ShadowApiReport with undocumented, unimplemented, and mismatches.
    """
    report = ShadowApiReport(
        total_spec_endpoints=len(spec_endpoints),
        total_traffic_endpoints=len(traffic_endpoints),
    )

    # Normalize spec endpoints for comparison
    spec_set: Dict[str, SpecEndpoint] = {}
    for se in spec_endpoints:
        key = f"{se.method}:{_normalize_openapi_path(se.path)}"
        spec_set[key] = se

    # Normalize traffic endpoints for comparison
    traffic_set: Dict[str, Any] = {}
    for eid, ep in traffic_endpoints.items():
        key = f"{ep.method}:{ep.path}"
        traffic_set[key] = ep

    # Find undocumented (in traffic, not in spec)
    for key, ep in traffic_set.items():
        if key not in spec_set:
            report.undocumented.append({
                "method": ep.method,
                "path": ep.path,
                "host": ep.host,
                "endpoint_id": ep.id,
                "risk": "Shadow API — not documented, may be untested or deprecated",
            })

    # Find unimplemented (in spec, not in traffic)
    for key, se in spec_set.items():
        if key not in traffic_set:
            report.unimplemented.append({
                "method": se.method,
                "path": se.path,
                "summary": se.summary,
                "deprecated": se.deprecated,
            })

    # Find parameter mismatches (in both, but params differ)
    for key in set(traffic_set.keys()) & set(spec_set.keys()):
        ep = traffic_set[key]
        se = spec_set[key]

        traffic_params = set(ep.params) if hasattr(ep, 'params') else set()
        spec_params = set(se.parameters + se.request_body_fields)

        extra_in_traffic = traffic_params - spec_params
        missing_from_traffic = spec_params - traffic_params

        if extra_in_traffic or missing_from_traffic:
            mismatch = {
                "method": ep.method,
                "path": ep.path,
                "extra_params": sorted(extra_in_traffic),
                "missing_params": sorted(missing_from_traffic),
            }
            if extra_in_traffic:
                mismatch["risk"] = (
                    f"Traffic uses {len(extra_in_traffic)} undocumented parameter(s): "
                    f"{', '.join(sorted(extra_in_traffic)[:5])}"
                )
            report.param_mismatches.append(mismatch)

    # Calculate coverage
    if spec_set:
        covered = len(set(traffic_set.keys()) & set(spec_set.keys()))
        report.coverage_percent = round(covered / len(spec_set) * 100, 1)

    return report
