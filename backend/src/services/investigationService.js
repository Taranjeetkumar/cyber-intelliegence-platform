const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");
const IOC = require("../models/IOC");
const HoneypotEvent = require("../models/HoneypotEvent");
const { checkIpReputation } = require("./abuseIpDbService");
const { checkIpThreatIntel } = require("./otxService");

// ── Helper: convert Neo4j Integer to JS number ─────────────────────────────
const toNum = (val) =>
  val && typeof val === "object" && "low" in val ? val.low : val;

//changes here 
const normalizeProperties = (properties = {}) =>
  Object.fromEntries(
    Object.entries(properties).map(([key, value]) => {
      if (Array.isArray(value)) {
        return [key, value.map((item) => toNum(item))];
      }

      return [key, toNum(value)];
    })
  );

const isPrivateOrLocalIp = (ip) =>
  ip === "127.0.0.1" ||
  ip === "::1" ||
  ip.startsWith("10.") ||
  ip.startsWith("192.168.") ||
  /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip);

const buildLocalReputation = (ipValue, events = []) => {
  const severityScore = events.reduce((max, event) => {
    const score = event.severity === "critical" ? 95 : event.severity === "high" ? 85 : event.severity === "medium" ? 60 : 35;
    return Math.max(max, score);
  }, 0);
  const confidence = Math.min(100, severityScore + Math.max(0, events.length - 1) * 3);
  const services = [...new Set(events.map((event) => event.service).filter(Boolean))];

  return {
    abuseIpDb: {
      configured: true,
      localVerdict: true,
      note: "Local honeypot verdict for private Docker IP. Not an AbuseIPDB public lookup.",
      data: {
        ipAddress: ipValue,
        abuseConfidenceScore: confidence,
        totalReports: events.length,
        countryCode: "private",
        isp: "Docker bridge / local lab",
        usageType: services.length ? `Honeypot target: ${services.join(", ")}` : "Honeypot target",
        lastReportedAt: events[0]?.capturedAt,
      },
    },
    otx: {
      configured: true,
      localVerdict: true,
      note: "Local honeypot verdict for private Docker IP. Not an AlienVault OTX public lookup.",
      general: {
        reputation: confidence >= 80 ? "malicious-lab-signal" : "suspicious-lab-signal",
        country_code: "private",
        asn: "Docker bridge / local lab",
        sections: ["honeypot", ...services],
        pulse_info: {
          count: events.length > 0 ? 1 : 0,
          pulses: events.length > 0
            ? [
                {
                  id: "local-honeypot-capture",
                  name: `${events.length} local honeypot event${events.length === 1 ? "" : "s"} captured`,
                  modified: events[0]?.capturedAt,
                },
              ]
            : [],
        },
      },
      reputation: {
        reputation: confidence,
      },
      errors: [],
    },
  };
};

const addSyntheticNode = (nodes, node) => {
  if (!nodes.some((existing) => existing.id === node.id)) {
    nodes.push(node);
  }
};

const addSyntheticEdge = (edges, edge) => {
  if (!edges.some((existing) => existing.id === edge.id)) {
    edges.push(edge);
  }
};

const tagToGroup = (tag = "") => {
  const normalized = tag.toLowerCase();
  if (normalized.startsWith("apt") || normalized.startsWith("ta") || normalized.includes("actor")) return "ThreatActor";
  if (normalized.includes("campaign")) return "Campaign";
  if (normalized.includes("c2") || normalized.includes("botnet") || normalized.includes("trojan") || normalized.includes("ransomware")) return "Malware";
  if (normalized.includes("phishing")) return "Campaign";
  return "Pulse";
};

const GRAPH_LABELS = new Set([
  "IP",
  "Domain",
  "Malware",
  "CVE",
  "Exploit",
  "Campaign",
  "ThreatActor",
  "Device",
  "Port",
  "Service",
  "Credential",
  "Pulse",
  "Reputation",
  "Geo",
  "ASN",
  "IntelSource",
  "Observation",
]);

const relationLabelToType = (label = "") =>
  label
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "") || "RELATED_TO";

const sanitizeGraphProperties = (properties = {}) =>
  Object.fromEntries(
    Object.entries(properties)
      .filter(([, value]) => value !== undefined)
      .map(([key, value]) => {
        if (value instanceof Date) return [key, value.toISOString()];
        if (Array.isArray(value)) return [key, value.map((item) => String(item))];
        if (value && typeof value === "object") return [key, JSON.stringify(value)];
        return [key, value];
      })
  );

const persistEvidenceGraphToNeo4j = async (session, graph) => {
  for (const node of graph.nodes) {
    const label = GRAPH_LABELS.has(node.group) ? node.group : "Observation";
    const properties = sanitizeGraphProperties(node.properties);

    await session.run(
      `
      MERGE (n:${label} {syntheticId: $id})
      SET n += $properties,
          n.label = $label,
          n.group = $group,
          n.lastSeen = datetime()
      `,
      {
        id: node.id,
        label: node.label,
        group: node.group,
        properties,
      }
    );
  }

  for (const edge of graph.edges) {
    const relType = relationLabelToType(edge.label);
    await session.run(
      `
      MATCH (from {syntheticId: $from})
      MATCH (to {syntheticId: $to})
      MERGE (from)-[r:${relType}]->(to)
      SET r.label = $label,
          r.lastSeen = datetime()
      `,
      {
        from: edge.from,
        to: edge.to,
        label: edge.label,
      }
    );
  }
};

const buildEvidenceGraph = ({ ipValue, mongoRecord, honeypotEvents, abuseIpDb, otx }) => {
  const nodes = [
    {
      id: `ip:${ipValue}`,
      label: ipValue,
      group: "IP",
      properties: { value: ipValue, source: "evidence_graph" },
      isRoot: true,
    },
  ];
  const edges = [];

  const abuseData = abuseIpDb?.data;
  const otxGeneral = otx?.general;
  const otxPulseInfo = otxGeneral?.pulse_info;
  const otxPulses = otxPulseInfo?.pulses || [];
  const confidence = mongoRecord?.confidence ?? abuseData?.abuseConfidenceScore ?? otx?.reputation?.reputation ?? 0;

  addSyntheticNode(nodes, {
    id: `reputation:${ipValue}`,
    label: `risk ${confidence}`,
    group: "Reputation",
    properties: {
      confidence,
      abuse_score: abuseData?.abuseConfidenceScore ?? "n/a",
      otx_reputation: otx?.reputation?.reputation ?? otxGeneral?.reputation ?? "n/a",
      source: abuseIpDb?.localVerdict || otx?.localVerdict ? "local verdict" : "live intel",
    },
  });
  addSyntheticEdge(edges, {
    id: `edge:${ipValue}:reputation`,
    from: `ip:${ipValue}`,
    to: `reputation:${ipValue}`,
    label: "has reputation",
  });

  addSyntheticNode(nodes, {
    id: `abuseipdb:${ipValue}`,
    label: abuseIpDb?.configured ? "AbuseIPDB" : "AbuseIPDB not configured",
    group: "IntelSource",
    properties: {
      source: "AbuseIPDB",
      configured: Boolean(abuseIpDb?.configured),
      local_verdict: Boolean(abuseIpDb?.localVerdict),
      error: abuseIpDb?.error || "",
      abuse_score: abuseData?.abuseConfidenceScore ?? "n/a",
      total_reports: abuseData?.totalReports ?? "n/a",
      country: abuseData?.countryCode || "n/a",
      isp: abuseData?.isp || "n/a",
      usage: abuseData?.usageType || "n/a",
      last_reported: abuseData?.lastReportedAt || "n/a",
    },
  });
  addSyntheticEdge(edges, {
    id: `edge:${ipValue}:abuseipdb`,
    from: `ip:${ipValue}`,
    to: `abuseipdb:${ipValue}`,
    label: "checked by",
  });

  const asnValue = abuseData?.asn || otxGeneral?.asn || mongoRecord?.enrichment?.asn;
  const countryValue = abuseData?.countryCode || otxGeneral?.country_name || otxGeneral?.country_code || mongoRecord?.enrichment?.whois_country;

  if (countryValue) {
    addSyntheticNode(nodes, {
      id: `geo:${ipValue}:${countryValue}`,
      label: countryValue,
      group: "Geo",
      properties: {
        country: countryValue,
        isp: abuseData?.isp || mongoRecord?.enrichment?.isp || "n/a",
        asn: asnValue || "n/a",
      },
    });
    addSyntheticEdge(edges, {
      id: `edge:${ipValue}:geo`,
      from: `reputation:${ipValue}`,
      to: `geo:${ipValue}:${countryValue}`,
      label: "located in",
    });
  }

  if (asnValue && asnValue !== "n/a") {
    addSyntheticNode(nodes, {
      id: `asn:${ipValue}:${asnValue}`,
      label: String(asnValue).slice(0, 28),
      group: "ASN",
      properties: {
        asn: asnValue,
        isp: abuseData?.isp || mongoRecord?.enrichment?.isp || "n/a",
        source: otxGeneral?.asn ? "AlienVault OTX" : "enrichment",
      },
    });
    addSyntheticEdge(edges, {
      id: `edge:${ipValue}:asn`,
      from: `ip:${ipValue}`,
      to: `asn:${ipValue}:${asnValue}`,
      label: "announced by",
    });
  }

  if (otxGeneral?.sections?.length > 0) {
    addSyntheticNode(nodes, {
      id: `otx:${ipValue}`,
      label: "OTX profile",
      group: "IntelSource",
      properties: {
        source: "AlienVault OTX",
        sections: otxGeneral.sections.join(", "),
        pulse_count: otxPulseInfo?.count ?? 0,
      },
    });
    addSyntheticEdge(edges, {
      id: `edge:${ipValue}:otx`,
      from: `ip:${ipValue}`,
      to: `otx:${ipValue}`,
      label: "profiled by",
    });

    otxGeneral.sections.slice(0, 6).forEach((section) => {
      addSyntheticNode(nodes, {
        id: `otx-section:${ipValue}:${section}`,
        label: section.replace(/_/g, " "),
        group: "Observation",
        properties: {
          section,
          source: "AlienVault OTX",
        },
      });
      addSyntheticEdge(edges, {
        id: `edge:${ipValue}:otx-section:${section}`,
        from: `otx:${ipValue}`,
        to: `otx-section:${ipValue}:${section}`,
        label: "has section",
      });
    });
  }

  (mongoRecord?.tags || []).forEach((tag) => {
    const group = tagToGroup(tag);
    addSyntheticNode(nodes, {
      id: `tag:${tag}`,
      label: tag,
      group,
      properties: { tag, source: mongoRecord.source || "mongo_ioc" },
    });
    addSyntheticEdge(edges, {
      id: `edge:${ipValue}:tag:${tag}`,
      from: `ip:${ipValue}`,
      to: `tag:${tag}`,
      label: "tagged",
    });
  });

  const services = new Map();
  honeypotEvents.forEach((event) => {
    const serviceName = (event.service || "unknown").toUpperCase();
    const serviceId = `service:${serviceName}`;
    const current = services.get(serviceId) || {
      count: 0,
      severities: new Set(),
      ports: new Set(),
      eventTypes: new Set(),
    };
    current.count += 1;
    if (event.severity) current.severities.add(event.severity);
    if (event.destinationPort) current.ports.add(event.destinationPort);
    if (event.eventType) current.eventTypes.add(event.eventType);
    services.set(serviceId, current);

    if (event.username) {
      const credentialId = `credential:${event.username}:${event.password || ""}`;
      addSyntheticNode(nodes, {
        id: credentialId,
        label: event.username,
        group: "Credential",
        properties: {
          username: event.username,
          password: event.password || "",
          capturedAt: event.capturedAt,
          service: serviceName,
        },
      });
      addSyntheticEdge(edges, {
        id: `edge:${ipValue}:credential:${event._id}`,
        from: `ip:${ipValue}`,
        to: credentialId,
        label: "attempted credential",
      });
    }
  });

  services.forEach((service, serviceId) => {
    addSyntheticNode(nodes, {
      id: serviceId,
      label: serviceId.replace("service:", ""),
      group: "Service",
      properties: {
        captured_events: service.count,
        severity: [...service.severities].join(", ") || "n/a",
        ports: [...service.ports].join(", ") || "n/a",
        event_types: [...service.eventTypes].join(", ") || "n/a",
      },
    });
    addSyntheticEdge(edges, {
      id: `edge:${ipValue}:${serviceId}`,
      from: `ip:${ipValue}`,
      to: serviceId,
      label: "targeted",
    });
  });

  otxPulses.slice(0, 5).forEach((pulse) => {
    const pulseId = `pulse:${pulse.id || pulse.name}`;
    addSyntheticNode(nodes, {
      id: pulseId,
      label: pulse.name || pulse.id,
      group: "Pulse",
      properties: {
        id: pulse.id || "",
        modified: pulse.modified || "",
        source: "AlienVault OTX",
      },
    });
    addSyntheticEdge(edges, {
      id: `edge:${ipValue}:pulse:${pulse.id || pulse.name}`,
      from: `ip:${ipValue}`,
      to: pulseId,
      label: "mentioned in",
    });
  });

  if (nodes.length === 2) {
    addSyntheticNode(nodes, {
      id: `observable:${ipValue}`,
      label: "no related intel yet",
      group: "Observation",
      properties: {
        next_steps: "Run Nmap, ingest IOC tags, capture honeypot traffic, or add API keys for richer enrichment.",
      },
    });
    addSyntheticEdge(edges, {
      id: `edge:${ipValue}:observable`,
      from: `ip:${ipValue}`,
      to: `observable:${ipValue}`,
      label: "needs enrichment",
    });
  }

  return {
    nodes,
    edges,
  };
};

// ── UC1: Traverse attack chain from a given IP ─────────────────────────────
// Strategy:
//   1. Neo4j  → variable-length path traversal (up to 5 hops)
//   2. MongoDB → full enrichment record for the starting IP
//   3. Redis  → check if any matched campaign is currently "active"
//
const investigateIP = async (ipValue) => {
  const session = getNeo4jSession();

  try {
    const cypher = `
      MATCH (start:IP {value: $ip})
      OPTIONAL MATCH path = (start)-[
        :RESOLVES_TO|HOSTS|EXPLOITS|USED_BY|OPERATES|OPERATED_BY|CONTACTED|HAS_PORT|RUNS|VULNERABLE_TO|HAS_EXPLOIT|TARGETED|ATTEMPTED_CREDENTIAL|MENTIONED_IN|HAS_REPUTATION|CHECKED_BY|LOCATED_IN|ANNOUNCED_BY|PROFILED_BY|HAS_SECTION|TAGGED|NEEDS_ENRICHMENT*1..5
      ]->(connected)
      WITH start,
           COLLECT(DISTINCT connected) AS connectedNodes,
           COLLECT(DISTINCT relationships(path)) AS relPaths
      RETURN
        start,
        connectedNodes,
        relPaths
    `;

    const mongoRecord = await IOC.findOne(
      { value: ipValue, type: "ip" },
      { enrichment: 1, tags: 1, confidence: 1, last_seen: 1, source: 1, analyst_notes: 1 }
    ).lean();

    const honeypotEvents = await HoneypotEvent.find({ sourceIp: ipValue })
      .sort({ capturedAt: -1 })
      .limit(8)
      .lean();

    const localReputation = buildLocalReputation(ipValue, honeypotEvents);
    const [abuseIpDb, otx] = isPrivateOrLocalIp(ipValue)
      ? [localReputation.abuseIpDb, localReputation.otx]
      : await Promise.all([
          checkIpReputation(ipValue),
          checkIpThreatIntel(ipValue),
        ]);

    const redis = getRedis();
    await redis.zIncrBy("hot:iocs", 1, ipValue);
    const evidenceGraph = buildEvidenceGraph({ ipValue, mongoRecord, honeypotEvents, abuseIpDb, otx });
    await persistEvidenceGraphToNeo4j(session, evidenceGraph);

    const result = await session.run(cypher, { ip: ipValue });

    if (result.records.length === 0) {
      return {
        found: true,
        evidenceGraph: true,
        graph: evidenceGraph,
        mongoDetail: mongoRecord,
        honeypotEvents,
        abuseIpDb,
        otx,
        activeCampaigns: [],
        stats: {
          totalNodes: evidenceGraph.nodes.length,
          totalEdges: evidenceGraph.edges.length,
          nodeTypes: [...new Set(evidenceGraph.nodes.map((node) => node.group))],
        },
      };
    }

    const record = result.records[0];
    const startNode = record.get("start");
    const connectedNodes = record.get("connectedNodes");
    const relPaths = record.get("relPaths").flat();

    const nodesMap = new Map();
    const edgesSet = new Set();

    // Add the start node
    nodesMap.set(startNode.identity.toString(), {
      id: startNode.identity.toString(),
      label: startNode.properties.value || "IP",
      group: "IP",
      properties: normalizeProperties(startNode.properties),
      isRoot: true,
    });

    // Add connected nodes
    connectedNodes.forEach((node) => {
      if (!node) return;
      const id = node.identity.toString();
      const label = node.labels[0];
      const displayLabel =
        node.properties.value ||
        node.properties.label ||
        node.properties.name ||
        node.properties.cve_id ||
        node.properties.module_name ||
        label;

      nodesMap.set(id, {
        id,
        label: displayLabel,
        group: label,
        properties: normalizeProperties(node.properties),
      });
    });

    // Add edges from all relationship arrays
    relPaths.forEach((rel) => {
      if (!rel) return;
      const edgeId = `${rel.start}-${rel.type}-${rel.end}`;
      if (!edgesSet.has(edgeId)) {
        edgesSet.add(edgeId);
      }
    });

    // const mongoRecord = await IOC.findOne(
    //   { value: ipValue, type: "ip" },
    //   { enrichment: 1, tags: 1, confidence: 1, last_seen: 1, source: 1, analyst_notes: 1 }
    // ).lean();

    const campaignNodes = [...nodesMap.values()].filter(
      (n) => n.group === "Campaign"
    );

    const activeCampaigns = [];
    for (const camp of campaignNodes) {
      const campId = camp.properties.campaign_id || camp.properties.name;
      if (campId) {
        const isActive = await redis.sIsMember("campaign:active", campId);
        if (isActive) activeCampaigns.push(campId);
      }
    }

    // ── Increment hit counter for this IP ───────────────────────────────────
    await redis.zIncrBy("hot:iocs", 1, ipValue);

    const edgeCypher = `
      MATCH (start:IP {value: $ip})
      OPTIONAL MATCH (a)-[r:RESOLVES_TO|HOSTS|EXPLOITS|USED_BY|OPERATES|VULNERABLE_TO|HAS_EXPLOIT*1..5]->(b)
        WHERE a = start OR (start)-[:RESOLVES_TO|HOSTS|EXPLOITS|USED_BY|OPERATES*1..4]->(a)
      RETURN DISTINCT
        id(startNode(r[-1])) AS fromId,
        id(endNode(r[-1]))   AS toId,
        type(r[-1])          AS relType
      LIMIT 200
    `;

    // Simpler direct approach — get all relationships for found nodes
    const nodeIds = [...nodesMap.keys()].map((id) => parseInt(id));
    const edgeCypher2 = `
      MATCH (a)-[r]->(b)
      WHERE id(a) IN $ids AND id(b) IN $ids
      RETURN id(a) AS fromId, id(b) AS toId, type(r) AS relType, id(r) AS relId
    `;

    const edgeResult = await session.run(edgeCypher2, { ids: nodeIds });
    const edges = edgeResult.records.map((rec) => ({
      id: `e_${toNum(rec.get("relId"))}`,
      from: toNum(rec.get("fromId")).toString(),
      to: toNum(rec.get("toId")).toString(),
      label: rec.get("relType").replace(/_/g, " ").toLowerCase(),
    }));

    if (nodesMap.size <= 1 || edges.length === 0) {
      return {
        found: true,
        evidenceGraph: true,
        graph: evidenceGraph,
        mongoDetail: mongoRecord,
        honeypotEvents,
        abuseIpDb,
        otx,
        activeCampaigns,
        stats: {
          totalNodes: evidenceGraph.nodes.length,
          totalEdges: evidenceGraph.edges.length,
          nodeTypes: [...new Set(evidenceGraph.nodes.map((node) => node.group))],
        },
      };
    }

    return {
      found: true,
      graph: {
        nodes: [...nodesMap.values()],
        edges,
      },
      mongoDetail: mongoRecord,
      honeypotEvents,
      abuseIpDb,
      otx,
      activeCampaigns,
      stats: {
        totalNodes: nodesMap.size,
        totalEdges: edges.length,
        nodeTypes: [...new Set([...nodesMap.values()].map((n) => n.group))],
      },
    };
  } finally {
    await session.close();
  }
};

// ── Get list of all known IPs (for the dropdown in the UI) ─────────────────
const listKnownIPs = async () => {
  const session = getNeo4jSession();
  try {
    const result = await session.run(
      "MATCH (i:IP) RETURN i.value AS value ORDER BY value LIMIT 100"
    );
    return result.records.map((r) => r.get("value"));
  } finally {
    await session.close();
  }
};

module.exports = { investigateIP, listKnownIPs };
