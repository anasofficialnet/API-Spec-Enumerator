"""
Unit tests for the 7 AASE Power Modules.
"""
import json
import pytest
import sys, os

# Ensure the backend directory is in the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.bola_detector import (
    _is_id_value, extract_resource_ids, build_bola_cases, analyze_bola_response,
)
from modules.stateful_fuzzer import (
    discover_chains, build_stateful_cases, analyze_stateful_response, _path_order_score,
)
from modules.race_engine import (
    identify_race_targets, build_race_burst, analyze_race_results,
)
from modules.ast_mutator import (
    generate_mutations, build_mutation_cases, analyze_mutation_response,
    _type_swap_mutations, _prototype_pollution_mutations, _extra_field_mutations,
)
from modules.shadow_api import (
    parse_openapi_spec, diff_traffic_vs_spec, _normalize_openapi_path,
)
from modules.patch_generator import generate_patches
from modules.graphql_ws import (
    detect_graphql_endpoints, build_graphql_fuzz_cases, analyze_graphql_response,
    detect_ws_endpoints, build_ws_fuzz_cases, analyze_ws_response,
    parse_introspection_result,
)


# ── Helpers ────────────────────────────────────────────────────────

class FakeRecord:
    def __init__(self, method, url, headers=None, body=None, status=None,
                 response_headers=None, response_body=None):
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.body = body
        self.status = status
        self.response_headers = response_headers or {}
        self.response_body = response_body


class FakeEndpoint:
    def __init__(self, eid, method, path, host, body_fields=None, params=None):
        self.id = eid
        self.method = method
        self.path = path
        self.host = host
        self.body_fields = body_fields or []
        self.params = params or []
        self.status_codes = [200]
        self.auth_required = False
        self.schema_confidence = 0.9
        self.fuzz_cases = 3


class FakeResponse:
    def __init__(self, status_code, content=b"", headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}


# ── Module 1: Cross-User Access ───────────────────────────────────

class TestBolaDetector:
    def test_is_id_value_numeric(self):
        assert _is_id_value("12345") is True
        assert _is_id_value("0") is True

    def test_is_id_value_uuid(self):
        assert _is_id_value("550e8400-e29b-41d4-a716-446655440000") is True

    def test_is_id_value_slug(self):
        assert _is_id_value("abc123-def") is True
        assert _is_id_value("hello") is False  # pure alpha

    def test_analyze_bola_access_denied(self):
        result = analyze_bola_response(b"data", b"denied", 403)
        assert result is None

    def test_analyze_bola_critical(self):
        baseline = b'{"user_id": "123", "name": "Alice", "email": "alice@test.com"}'
        cross = b'{"user_id": "123", "name": "Alice", "email": "alice@test.com"}'
        result = analyze_bola_response(baseline, cross, 200)
        assert result is not None
        assert result["severity"] == "CRITICAL"
        assert result["type"] == "Cross-User Access Control Bypass"
        assert result["cwe"] == "CWE-639"

    def test_analyze_bola_moderate_similarity(self):
        baseline = b'{"user_id": "123"}'
        cross = b'{"user_id": "456", "different": true}'
        result = analyze_bola_response(baseline, cross, 200)
        assert result is not None
        assert result["severity"] in ("CRITICAL", "HIGH")

    def test_analyze_bola_includes_resource_id_when_available(self):
        baseline = b'{"user_id": "123"}'
        cross = b'{"user_id": "123"}'
        result = analyze_bola_response(baseline, cross, 200, {"resource_id": "order-123"})
        assert result is not None
        assert "order-123" in result["evidence"]

    def test_build_bola_cases(self):
        rec = FakeRecord("GET", "http://api.test.com/users/123",
                         headers={"Authorization": "Bearer token_a"})
        ep = FakeEndpoint("ep1", "GET", "/users/{id}", "api.test.com")
        endpoints = {"ep1": ep}
        records = [rec]
        ua = {"bearer": "token_a"}
        ub = {"bearer": "token_b"}
        cases = build_bola_cases(records, endpoints, ua, ub)
        assert isinstance(cases, list)


# ── Module 2: Stateful Fuzzer ─────────────────────────────────────

class TestStatefulFuzzer:
    def test_path_order_score(self):
        assert _path_order_score("/api/create") > 0
        assert _path_order_score("/api/checkout") > _path_order_score("/api/create")
        assert _path_order_score("/api/static") == 0

    def test_discover_chains(self):
        records = [
            FakeRecord("POST", "http://api.test.com/cart",
                       headers={"Authorization": "Bearer x"}),
            FakeRecord("POST", "http://api.test.com/checkout",
                       headers={"Authorization": "Bearer x"}),
        ]
        ep1 = FakeEndpoint("ep1", "POST", "/cart", "api.test.com")
        ep2 = FakeEndpoint("ep2", "POST", "/checkout", "api.test.com")
        endpoints = {"ep1": ep1, "ep2": ep2}
        chains = discover_chains(records, endpoints)
        assert len(chains) >= 1
        assert len(chains[0].steps) == 2

    def test_build_stateful_cases_skip(self):
        records = [
            FakeRecord("POST", "http://api.test.com/cart",
                       headers={"Authorization": "Bearer x"}),
            FakeRecord("POST", "http://api.test.com/checkout",
                       headers={"Authorization": "Bearer x"}),
        ]
        ep1 = FakeEndpoint("ep1", "POST", "/cart", "api.test.com")
        ep2 = FakeEndpoint("ep2", "POST", "/checkout", "api.test.com")
        endpoints = {"ep1": ep1, "ep2": ep2}
        chains = discover_chains(records, endpoints)
        if chains:
            cases = build_stateful_cases(chains[0])
            assert any(c["id"] == "stateful_skip" for c in cases)

    def test_analyze_stateful_skip_success(self):
        case = {
            "id": "stateful_skip",
            "stateful_meta": {
                "chain_id": "abc",
                "attack": "skip_step",
                "skipped_step": 0,
                "chain_desc": "test chain",
            },
        }
        result = analyze_stateful_response(case, 200, b'{"ok": true}')
        assert result is not None
        assert result["severity"] == "HIGH"
        assert result["type"] == "Workflow Step Bypass"

    def test_analyze_stateful_blocked(self):
        case = {
            "id": "stateful_skip",
            "stateful_meta": {"attack": "skip_step", "chain_id": "abc"},
        }
        result = analyze_stateful_response(case, 403, b"Forbidden")
        assert result is None


# ── Module 3: Race Engine ─────────────────────────────────────────

class TestRaceEngine:
    def test_identify_race_targets(self):
        ep1 = FakeEndpoint("ep1", "POST", "/api/transfer", "api.test.com",
                           body_fields=["amount"])
        ep2 = FakeEndpoint("ep2", "GET", "/api/balance", "api.test.com")
        ep3 = FakeEndpoint("ep3", "POST", "/graphql", "api.test.com", body_fields=["query"])
        endpoints = {"ep1": ep1, "ep2": ep2, "ep3": ep3}
        targets = identify_race_targets(endpoints)
        assert "ep1" in targets
        assert "ep2" not in targets
        assert "ep3" not in targets

    def test_build_race_burst(self):
        rec = FakeRecord("POST", "http://api.test.com/api/transfer",
                         headers={"Authorization": "Bearer x"},
                         body=b'{"amount": 100}')
        ep = FakeEndpoint("ep1", "POST", "/api/transfer", "api.test.com")
        burst = build_race_burst(rec, ep, burst_size=5)
        assert len(burst) == 5
        assert all(c["id"] == "race_burst" for c in burst)
        assert all(c["race_meta"]["burst_size"] == 5 for c in burst)

    def test_analyze_race_multiple_success(self):
        case1 = {"race_meta": {"burst_id": "x", "burst_index": 0, "burst_size": 5}}
        case2 = {"race_meta": {"burst_id": "x", "burst_index": 1, "burst_size": 5}}
        resp1 = FakeResponse(200, b'{"id": "abc"}')
        resp2 = FakeResponse(200, b'{"id": "def"}')
        results = [(case1, resp1), (case2, resp2)]
        finding = analyze_race_results(results)
        assert finding is not None
        assert finding["severity"] == "CRITICAL"  # Different responses
        assert "Race Condition" in finding["type"]

    def test_analyze_race_all_fail(self):
        case1 = {"race_meta": {"burst_id": "x", "burst_index": 0, "burst_size": 5}}
        resp1 = FakeResponse(429, b"Too Many Requests")
        results = [(case1, resp1)]
        finding = analyze_race_results(results)
        assert finding is None


# ── Module 4: AST Mutator ─────────────────────────────────────────

class TestAstMutator:
    def test_type_swap_mutations(self):
        body = {"name": "Alice", "age": 30}
        mutations = _type_swap_mutations(body)
        assert len(mutations) > 0
        # Should have integer swapped to string
        assert any(isinstance(m.get("age"), str) for m in mutations)

    def test_prototype_pollution(self):
        body = {"name": "Alice"}
        mutations = _prototype_pollution_mutations(body)
        assert len(mutations) >= 4
        assert any("__proto__" in m for m in mutations)

    def test_extra_fields(self):
        body = {"name": "Alice"}
        mutations = _extra_field_mutations(body)
        assert any("admin" in m for m in mutations)
        assert any("role" in m for m in mutations)

    def test_generate_mutations(self):
        body = {"user": "test", "amount": 100}
        mutations = generate_mutations(body)
        assert len(mutations) > 10  # Should generate many mutations
        types = {m["type"] for m in mutations}
        assert "type_swap" in types
        assert "prototype_pollution" in types
        assert "extra_fields" in types

    def test_analyze_mutation_server_error(self):
        case = {"mutation_meta": {"mutation_type": "type_swap"}}
        result = analyze_mutation_response(case, 500, b"Error")
        assert result is not None
        assert result["severity"] == "MEDIUM"

    def test_analyze_mutation_mass_assignment(self):
        case = {"mutation_meta": {"mutation_type": "extra_fields"}}
        body = b'{"admin": true, "role": "admin"}'
        result = analyze_mutation_response(case, 200, body)
        assert result is not None
        assert result["severity"] == "CRITICAL"
        assert "Mass Assignment" in result["type"]


# ── Module 5: Shadow API ──────────────────────────────────────────

class TestShadowApi:
    def test_normalize_path(self):
        assert _normalize_openapi_path("/users/{userId}") == "/users/{id}"
        assert _normalize_openapi_path("/api/v1/{tenant_id}/orders/{order_id}") == "/api/v1/{id}/orders/{id}"

    def test_parse_openapi_v3(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/users": {
                    "get": {"summary": "List users"},
                    "post": {"summary": "Create user"},
                },
                "/users/{id}": {
                    "get": {"summary": "Get user", "parameters": [{"name": "id", "in": "path"}]},
                },
            },
        }
        content = json.dumps(spec).encode()
        endpoints = parse_openapi_spec(content, "json")
        assert len(endpoints) == 3

    def test_parse_openapi_v2(self):
        spec = {
            "swagger": "2.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/items": {
                    "get": {"summary": "List items"},
                },
            },
        }
        content = json.dumps(spec).encode()
        endpoints = parse_openapi_spec(content, "json")
        assert len(endpoints) == 1

    def test_diff_undocumented(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {"/users": {"get": {"summary": "List"}}},
        }
        spec_eps = parse_openapi_spec(json.dumps(spec).encode(), "json")
        traffic_eps = {
            "ep1": FakeEndpoint("ep1", "GET", "/users", "api.test.com"),
            "ep2": FakeEndpoint("ep2", "GET", "/admin/secret", "api.test.com"),
        }
        report = diff_traffic_vs_spec(traffic_eps, spec_eps)
        assert len(report.undocumented) >= 1
        assert any("/admin/secret" in e["path"] for e in report.undocumented)

    def test_diff_coverage(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {"get": {"summary": "List"}},
                "/orders": {"get": {"summary": "List"}},
            },
        }
        spec_eps = parse_openapi_spec(json.dumps(spec).encode(), "json")
        traffic_eps = {
            "ep1": FakeEndpoint("ep1", "GET", "/users", "api.test.com"),
        }
        report = diff_traffic_vs_spec(traffic_eps, spec_eps)
        assert report.coverage_percent == 50.0


# ── Module 6: Patch Generator ─────────────────────────────────────

class TestPatchGenerator:
    def test_generate_sqli_patches(self):
        findings = [{"type": "SQLi", "severity": "HIGH", "endpoint": "/api/users"}]
        patches = generate_patches(findings)
        assert len(patches) >= 2  # Python + ModSecurity
        assert any(p["language"] == "python" for p in patches)
        assert any(p["language"] == "modsecurity" for p in patches)

    def test_generate_bola_patches(self):
        findings = [{"type": "Cross-User Access Control Bypass", "severity": "CRITICAL", "endpoint": "/api/data"}]
        patches = generate_patches(findings)
        assert len(patches) >= 1
        assert "ownership" in patches[0]["code"].lower() or "owner" in patches[0]["code"].lower()

    def test_generate_race_patches(self):
        findings = [{"type": "Race Condition (TOCTOU)", "severity": "HIGH"}]
        patches = generate_patches(findings)
        assert len(patches) >= 1
        assert "idempotency" in patches[0]["code"].lower() or "for_update" in patches[0]["code"].lower()

    def test_no_patches_for_unknown(self):
        findings = [{"type": "unknown_type_xyz", "severity": "LOW"}]
        patches = generate_patches(findings)
        assert len(patches) == 0

    def test_multiple_findings(self):
        findings = [
            {"type": "SQLi", "severity": "HIGH"},
            {"type": "XSS", "severity": "MEDIUM"},
            {"type": "CORS", "severity": "LOW"},
        ]
        patches = generate_patches(findings)
        types = {p["finding_type"] for p in patches}
        assert "SQLi" in types
        assert "XSS" in types
        assert "CORS" in types


# ── Module 7: GraphQL & WebSocket ──────────────────────────────────

class TestGraphqlWs:
    def test_detect_graphql_by_path(self):
        records = [
            FakeRecord("POST", "http://api.test.com/graphql",
                       headers={"Content-Type": "application/json"},
                       body=b'{"query": "{ users { id } }"}'),
        ]
        ep = FakeEndpoint("ep1", "POST", "/graphql", "api.test.com")
        endpoints = {"ep1": ep}
        gql_eps = detect_graphql_endpoints(records, endpoints)
        assert len(gql_eps) == 1

    def test_detect_graphql_by_body(self):
        records = [
            FakeRecord("POST", "http://api.test.com/api/v2",
                       headers={"Content-Type": "application/json"},
                       body=b'{"query": "mutation { createUser(name: \\"test\\") { id } }"}'),
        ]
        ep = FakeEndpoint("ep1", "POST", "/api/v2", "api.test.com")
        endpoints = {"ep1": ep}
        gql_eps = detect_graphql_endpoints(records, endpoints)
        assert len(gql_eps) == 1

    def test_build_graphql_fuzz_cases(self):
        from modules.graphql_ws import GraphQLEndpoint
        gql_ep = GraphQLEndpoint(
            endpoint_id="ep1", url="http://api.test.com/graphql",
            host="api.test.com", headers={"Content-Type": "application/json"},
        )
        cases = build_graphql_fuzz_cases(gql_ep)
        assert len(cases) >= 5  # introspection, depth, batch, field_suggest, alias
        ids = {c["id"] for c in cases}
        assert "graphql_introspection" in ids
        assert "graphql_depth_dos" in ids
        assert "graphql_batch" in ids

    def test_analyze_graphql_introspection_enabled(self):
        case = {"graphql_meta": {"attack": "introspection"}}
        body = b'{"data": {"__schema": {"queryType": {"name": "Query"}}}}'
        result = analyze_graphql_response(case, 200, body)
        assert result is not None
        assert result["type"] == "GraphQL Introspection Enabled"

    def test_detect_ws_endpoints(self):
        records = [
            FakeRecord("GET", "http://api.test.com/ws/chat",
                       headers={"Upgrade": "websocket", "Connection": "Upgrade"}),
        ]
        ep = FakeEndpoint("ep1", "GET", "/ws/chat", "api.test.com")
        endpoints = {"ep1": ep}
        ws_eps = detect_ws_endpoints(records, endpoints)
        assert len(ws_eps) == 1
        assert ws_eps[0].protocol == "ws"

    def test_build_ws_fuzz_cases(self):
        from modules.graphql_ws import WSEndpoint
        ws_ep = WSEndpoint(
            endpoint_id="ep1", url="ws://api.test.com/ws/chat",
            host="api.test.com", headers={"Authorization": "Bearer x"},
        )
        cases = build_ws_fuzz_cases(ws_ep)
        assert len(cases) == 3  # cswsh, evil_origin, no_auth
        assert any(c["ws_meta"]["attack"] == "cswsh" for c in cases)

    def test_analyze_ws_cswsh_vulnerable(self):
        case = {"ws_meta": {"attack": "cswsh"}}
        result = analyze_ws_response(case, 101, b"")
        assert result is not None
        assert result["severity"] == "HIGH"
        assert "CSWSH" in result["type"]

    def test_analyze_ws_blocked(self):
        case = {"ws_meta": {"attack": "evil_origin"}}
        result = analyze_ws_response(case, 403, b"Forbidden")
        assert result is None

    def test_parse_introspection_result(self):
        data = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {"name": "Query", "kind": "OBJECT", "fields": [
                            {"name": "users", "type": {"name": "User", "kind": "OBJECT", "ofType": None}},
                            {"name": "orders", "type": {"name": "Order", "kind": "OBJECT", "ofType": None}},
                        ]},
                        {"name": "Mutation", "kind": "OBJECT", "fields": [
                            {"name": "createUser", "type": {"name": "User", "kind": "OBJECT", "ofType": None}},
                        ]},
                        {"name": "User", "kind": "OBJECT", "fields": [
                            {"name": "id", "type": {"name": "ID", "kind": "SCALAR", "ofType": None}},
                            {"name": "name", "type": {"name": "String", "kind": "SCALAR", "ofType": None}},
                        ]},
                    ],
                }
            }
        }
        result = parse_introspection_result(data)
        assert "users" in result["queries"]
        assert "orders" in result["queries"]
        assert "createUser" in result["mutations"]
        assert any(t["name"] == "User" for t in result["types"])
