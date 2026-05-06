/**
 * UC4 — Identify At-Risk Devices
 * Primary DB: Neo4j + MongoDB + Redis (all three together)
 * Shows off: multi-hop Cypher query, cross-DB lookup, Redis TTL cache
 */
const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");
const IOC = require("../models/IOC");

const toNum = (val) =>
  val && typeof val === "object" && "low" in val ? val.low : Number(val);

// Find all devices with a complete exploit chain: Device→Port→Service→CVE→Exploit
// Then enrich each with Redis risk score and MongoDB scan details
const getAtRiskDevices = async (minCvss = 7.0) => {
  const session = getNeo4jSession();
  const redis = getRedis();

  try {
    // ── Step 1: Neo4j — find devices with full exploit chain ──────────────
    const cypher = `
      MATCH (d:Device)-[:HAS_PORT]->(p:Port)
            -[:RUNS]->(s:Service)
            -[:VULNERABLE_TO]->(c:CVE)
            -[:HAS_EXPLOIT]->(e:Exploit)
      WHERE c.cvss_score >= $minCvss
      RETURN
        d.hostname        AS hostname,
        d.ip              AS ip,
        d.os              AS os,
        c.cve_id          AS cve_id,
        c.cvss_score      AS cvss_score,
        c.description     AS cve_description,
        e.module_name     AS exploit_module,
        e.reliability     AS reliability,
        p.number          AS port,
        s.name            AS service,
        s.version         AS service_version
      ORDER BY c.cvss_score DESC
    `;

    const result = await session.run(cypher, { minCvss });
    const neoRows = result.records.map((r) => ({
      hostname:        r.get("hostname"),
      ip:              r.get("ip"),
      os:              r.get("os"),
      cve_id:          r.get("cve_id"),
      cvss_score:      toNum(r.get("cvss_score")),
      cve_description: r.get("cve_description"),
      exploit_module:  r.get("exploit_module"),
      reliability:     r.get("reliability"),
      port:            toNum(r.get("port")),
      service:         r.get("service"),
      service_version: r.get("service_version"),
    }));

    if (!neoRows.length) return [];

    // ── Step 2: Redis — get cached risk scores (fast, no DB hit) ─────────
    const uniqueHostnames = [...new Set(neoRows.map((r) => r.hostname))];

    const riskScores = {};
    await Promise.all(
      uniqueHostnames.map(async (host) => {
        const score = await redis.get(`risk:host:${host}`);
        riskScores[host] = score ? parseInt(score) : null;
      })
    );

    // ── Step 3: Group by device and attach risk scores ────────────────────
    const deviceMap = {};
    neoRows.forEach((row) => {
      if (!deviceMap[row.hostname]) {
        deviceMap[row.hostname] = {
          hostname:    row.hostname,
          ip:          row.ip,
          os:          row.os,
          redis_risk:  riskScores[row.hostname],
          vulnerabilities: [],
        };
      }
      deviceMap[row.hostname].vulnerabilities.push({
        cve_id:          row.cve_id,
        cvss_score:      row.cvss_score,
        cve_description: row.cve_description,
        exploit_module:  row.exploit_module,
        reliability:     row.reliability,
        port:            row.port,
        service:         row.service,
        service_version: row.service_version,
      });
    });

    // Compute final risk: max CVSS * 10 if Redis score missing
    const devices = Object.values(deviceMap).map((d) => {
      const maxCvss = Math.max(...d.vulnerabilities.map((v) => v.cvss_score));
      return {
        ...d,
        final_risk: d.redis_risk ?? Math.round(maxCvss * 10),
        vuln_count: d.vulnerabilities.length,
      };
    });

    return devices.sort((a, b) => b.final_risk - a.final_risk);
  } finally {
    await session.close();
  }
};

module.exports = { getAtRiskDevices };
