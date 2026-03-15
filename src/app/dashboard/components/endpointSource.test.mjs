import test from "node:test";
import assert from "node:assert/strict";

import {
  buildEndpointSourceTooltip,
  compareEndpointsBySource,
  getEndpointSourcePresentation,
  sortSourcesByPriority,
} from "./endpointSource.js";

test("maps captured traffic source label", () => {
  const presentation = getEndpointSourcePresentation({
    primary_source: "traffic",
    all_sources: ["traffic"],
    discovery_status: null,
  });

  assert.equal(presentation.label, "Captured Traffic");
  assert.equal(presentation.statusLabel, null);
});

test("includes additional sources and discovery status in tooltip", () => {
  const tooltip = buildEndpointSourceTooltip({
    primary_source: "seed_probe",
    all_sources: ["seed_probe", "crawl", "spec"],
    discovery_status: "confirmed",
    source_statuses: {
      seed_probe: "confirmed",
      crawl: "derived",
      spec: "derived",
    },
  });

  assert.match(tooltip, /Recon Guess/);
  assert.match(tooltip, /Status: Confirmed/);
  assert.match(tooltip, /Frontend Discovery \(Derived\)/);
  assert.match(tooltip, /API Documentation \(Derived\)/);
});

test("sorts sources by trust with captured traffic first and recon guess later", () => {
  const sorted = sortSourcesByPriority(["seed_probe", "traffic", "response_link", "spec", "unknown"]);
  assert.deepEqual(sorted, ["traffic", "spec", "response_link", "seed_probe", "unknown"]);
});

test("sorts endpoint rows by source priority", () => {
  const endpoints = [
    { primary_source: "seed_probe", method: "GET", path: "/graphql", host: "example.com" },
    { primary_source: "traffic", method: "GET", path: "/users/{id}", host: "example.com" },
    { primary_source: "spec", method: "POST", path: "/orders", host: "example.com" },
  ];

  endpoints.sort(compareEndpointsBySource);

  assert.equal(endpoints[0].primary_source, "traffic");
  assert.equal(endpoints[1].primary_source, "spec");
  assert.equal(endpoints[2].primary_source, "seed_probe");
});
