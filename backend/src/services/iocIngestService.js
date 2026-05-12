const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");
const IOC = require("../models/IOC");

// Simulate enrichment (in real system calls VirusTotal/WHOIS APIs)
const mockEnrich = (ioc) => ({
  whois_country: ["RU", "CN", "US", "DE", "BR"][Math.floor(Math.random() * 5)],
  asn: `AS${10000 + Math.floor(Math.random() * 50000)}`,
  virustotal_score: `${Math.floor(Math.random() * 60)}/${72}`,
  isp: "Mock ISP Ltd",
});

// Ingest a single IOC: deduplicate → enrich → MongoDB upsert → Neo4j MERGE
const ingestSingleIOC = async (ioc) => {
  const { value, type, tags = [], source = "manual", confidence = 50 } = ioc;
  if (!value || !type) throw new Error("value and type are required");

  const enrichment = mockEnrich(ioc);
  const now = new Date();

  const mongoResult = await IOC.findOneAndUpdate(
    { value, type },
    {
      $set:         { last_seen: now, tags, source, confidence, enrichment },
      $setOnInsert: { first_seen: now },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

  const isNew = !mongoResult.first_seen || 
    Math.abs(mongoResult.first_seen - now) < 1000;

  const session = getNeo4jSession();
  try {
    let cypher;
    if (type === "ip") {
      cypher = `
        MERGE (i:IP {value: $value})
        ON CREATE SET i.first_seen = $ts, i.country = $country, i.asn = $asn, i.confidence = $confidence
        ON MATCH  SET i.last_seen  = $ts, i.confidence = $confidence
        RETURN i
      `;
    } else if (type === "domain") {
      cypher = `
        MERGE (d:Domain {value: $value})
        ON CREATE SET d.first_seen = $ts, d.country = $country
        ON MATCH  SET d.last_seen  = $ts
        RETURN d
      `;
    } else {
      cypher = `
        MERGE (h:Hash {value: $value})
        ON CREATE SET h.first_seen = $ts, h.type = $type
        ON MATCH  SET h.last_seen  = $ts
        RETURN h
      `;
    }

    await session.run(cypher, {
      value,
      ts: now.toISOString(),
      country: enrichment.whois_country,
      asn: enrichment.asn,
      confidence,
      type,
    });
  } finally {
    await session.close();
  }

  // ── Redis: increment ingestion counter ────────────────────────────────────
  const redis = getRedis();
  await redis.incr(`stats:ingested:${type}`);

  return {
    status: isNew ? "created" : "updated",
    value,
    type,
    enrichment,
    mongo_id: mongoResult._id,
  };
};

// Batch ingest
const ingestBatch = async (iocs) => {
  const results = [];
  for (const ioc of iocs) {
    try {
      const r = await ingestSingleIOC(ioc);
      results.push({ ...r, error: null });
    } catch (err) {
      results.push({ value: ioc.value, error: err.message });
    }
  }
  return results;
};

// Get ingestion stats from Redis counters
const getIngestionStats = async () => {
  const redis = getRedis();
  const types = ["ip", "domain", "hash", "url"];
  const stats = {};
  for (const t of types) {
    const count = await redis.get(`stats:ingested:${t}`);
    stats[t] = count ? parseInt(count) : 0;
  }
  stats.total = Object.values(stats).reduce((a, b) => a + b, 0);
  return stats;
};

module.exports = { ingestSingleIOC, ingestBatch, getIngestionStats };
