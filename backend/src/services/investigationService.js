const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");
const IOC = require("../models/IOC");
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

// ── UC1: Traverse attack chain from a given IP ─────────────────────────────
// Strategy:
//   1. Neo4j  → variable-length path traversal (up to 5 hops)
//   2. MongoDB → full enrichment record for the starting IP
//   3. Redis  → check if any matched campaign is currently "active"
//
const investigateIP = async (ipValue) => {
  const session = getNeo4jSession();

  try {
    // ── Step 1: Neo4j variable-length path traversal ────────────────────────
    // We follow any of these relationship types up to 5 hops from the IP node.
    // COLLECT(DISTINCT ...) avoids duplicate nodes/rels in the response.
    const cypher = `
      MATCH (start:IP {value: $ip})
      OPTIONAL MATCH path = (start)-[
        :RESOLVES_TO|HOSTS|EXPLOITS|USED_BY|OPERATES|OPERATED_BY|CONTACTED|HAS_PORT|RUNS|VULNERABLE_TO|HAS_EXPLOIT*1..5
      ]->(connected)
      WITH start,
           COLLECT(DISTINCT connected) AS connectedNodes,
           COLLECT(DISTINCT relationships(path)) AS relPaths
      RETURN
        start,
        connectedNodes,
        relPaths
    `;

    const result = await session.run(cypher, { ip: ipValue });

    const mongoRecord = await IOC.findOne(
      { value: ipValue, type: "ip" },
      { enrichment: 1, tags: 1, confidence: 1, last_seen: 1, source: 1, analyst_notes: 1 }
    ).lean();

    const [abuseIpDb, otx] = await Promise.all([
      checkIpReputation(ipValue),
      checkIpThreatIntel(ipValue),
    ]);

    const redis = getRedis();
    await redis.zIncrBy("hot:iocs", 1, ipValue);

    if (result.records.length === 0) {
      const liveNode = {
        id: ipValue,
        label: ipValue,
        group: "IP",
        properties: { value: ipValue, source: "live_threat_intel_lookup" },
        isRoot: true,
      };

      return {
        found: true,
        threatOnly: true,
        graph: {
          nodes: [liveNode],
          edges: [],
        },
        mongoDetail: mongoRecord,
        abuseIpDb,
        otx,
        activeCampaigns: [],
        stats: {
          totalNodes: 1,
          totalEdges: 0,
          nodeTypes: ["IP"],
        },
      };
    }

    const record = result.records[0];
    const startNode = record.get("start");
    const connectedNodes = record.get("connectedNodes");
    const relPaths = record.get("relPaths").flat();

    // ── Build vis.js-compatible node + edge arrays ──────────────────────────
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

    // ── Step 2: MongoDB enrichment record ───────────────────────────────────
    // ── Step 3: Redis — which campaigns from this path are currently active? ─
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
    // ── Build edge list with labels ─────────────────────────────────────────
    // Re-query for edges with full relationship data
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

    return {
      found: true,
      graph: {
        nodes: [...nodesMap.values()],
        edges,
      },
      mongoDetail: mongoRecord,
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
