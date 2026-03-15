const SOURCE_META = {
  traffic: {
    label: "Captured Traffic",
    description: "Found in uploaded HTTP traffic such as HAR or Burp logs.",
  },
  seed_probe: {
    label: "Recon Guess",
    description: "Generated from common API paths during Auto-Recon.",
  },
  crawl: {
    label: "Frontend Discovery",
    description: "Extracted from HTML or JavaScript files.",
  },
  response_link: {
    label: "Response Discovery",
    description: "Extracted from API responses.",
  },
  spec: {
    label: "API Documentation",
    description: "Extracted from Swagger/OpenAPI documentation.",
  },
  unknown: {
    label: "Unknown",
    description: "Source metadata was not available for this endpoint.",
  },
};

const SOURCE_PRIORITY = {
  traffic: 5,
  spec: 4,
  crawl: 3,
  response_link: 2,
  seed_probe: 1,
  unknown: 0,
};

const DISCOVERY_STATUS_LABELS = {
  guessed: "Guessed",
  confirmed: "Confirmed",
  failed: "Failed",
  derived: "Derived",
};

export function getEndpointSourceMeta(source) {
  if (!source || !SOURCE_META[source]) {
    return SOURCE_META.unknown;
  }
  return SOURCE_META[source];
}

export function formatDiscoveryStatus(status) {
  if (!status || !DISCOVERY_STATUS_LABELS[status]) {
    return null;
  }
  return DISCOVERY_STATUS_LABELS[status];
}

export function sortSourcesByPriority(sources) {
  return [...sources].sort((left, right) => {
    const leftPriority = SOURCE_PRIORITY[left] ?? SOURCE_PRIORITY.unknown;
    const rightPriority = SOURCE_PRIORITY[right] ?? SOURCE_PRIORITY.unknown;
    if (leftPriority !== rightPriority) {
      return rightPriority - leftPriority;
    }
    return left.localeCompare(right);
  });
}

export function compareEndpointsBySource(left, right) {
  const leftSource = left?.primary_source || "unknown";
  const rightSource = right?.primary_source || "unknown";
  const leftPriority = SOURCE_PRIORITY[leftSource] ?? SOURCE_PRIORITY.unknown;
  const rightPriority = SOURCE_PRIORITY[rightSource] ?? SOURCE_PRIORITY.unknown;

  if (leftPriority !== rightPriority) {
    return rightPriority - leftPriority;
  }

  if (left.method !== right.method) {
    return left.method.localeCompare(right.method);
  }

  if (left.path !== right.path) {
    return left.path.localeCompare(right.path);
  }

  return left.host.localeCompare(right.host);
}

export function buildEndpointSourceTooltip(endpoint) {
  const primarySource = endpoint?.primary_source || "unknown";
  const primaryMeta = getEndpointSourceMeta(primarySource);
  const lines = [primaryMeta.label, primaryMeta.description];

  const status = formatDiscoveryStatus(endpoint?.discovery_status || null);
  if (status) {
    lines.push(`Status: ${status}`);
  }

  const allSources = Array.isArray(endpoint?.all_sources) && endpoint.all_sources.length > 0
    ? endpoint.all_sources
    : [primarySource];
  const sourceStatuses = endpoint?.source_statuses || {};
  const extraSources = sortSourcesByPriority(allSources.filter((source) => source !== primarySource));
  if (extraSources.length > 0) {
    const formatted = extraSources.map((source) => {
      const meta = getEndpointSourceMeta(source);
      const extraStatus = formatDiscoveryStatus(sourceStatuses[source] || null);
      return extraStatus ? `${meta.label} (${extraStatus})` : meta.label;
    });
    lines.push(`Also seen via: ${formatted.join(", ")}`);
  }

  return lines.join("\n");
}

export function getEndpointSourcePresentation(endpoint) {
  const primarySource = endpoint?.primary_source || "unknown";
  const primaryMeta = getEndpointSourceMeta(primarySource);
  return {
    ...primaryMeta,
    source: primarySource,
    statusLabel: formatDiscoveryStatus(endpoint?.discovery_status || null),
    tooltip: buildEndpointSourceTooltip(endpoint),
  };
}
