const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");
const Alert = require("../models/Alert");

const toNum = (val) =>
  val && typeof val === "object" && "low" in val ? val.low : Number(val);

// Core correlation: read hot IOCs from Redis → check campaign membership in Neo4j
const runCorrelation = async (topN = 20, threshold = 2) => {
  const redis = getRedis();

  const topIocs = await redis.zRangeWithScores("hot:iocs", 0, topN - 1, { REV: true });
  if (!topIocs.length) return { alerts: [], matched_campaigns: [] };

  const ipList = topIocs.map((i) => i.value);

  // Uses IN predicate + COUNT(DISTINCT) — key non-trivial Neo4j feature
  const session = getNeo4jSession();
  let campaignMatches = [];

  try {
    const cypher = `
      MATCH (i:IP)-[:RESOLVES_TO|HOSTS*1..3]->(m:Malware)-[:USED_BY]->(c:Campaign)
      WHERE i.value IN $ipList
      WITH c, COLLECT(DISTINCT i.value) AS matchedIPs, COUNT(DISTINCT i) AS matchCount
      WHERE matchCount >= $threshold
      MATCH (c)-[:OPERATED_BY]->(a:ThreatActor)
      RETURN
        c.name         AS campaign_name,
        c.campaign_id  AS campaign_id,
        a.name         AS actor_name,
        matchCount     AS matched_count,
        matchedIPs     AS matched_ips
      ORDER BY matchCount DESC
    `;

    const result = await session.run(cypher, {
      ipList,
      threshold: threshold,
    });

    campaignMatches = result.records.map((r) => ({
      campaign_name: r.get("campaign_name"),
      campaign_id:   r.get("campaign_id"),
      actor_name:    r.get("actor_name"),
      matched_count: toNum(r.get("matched_count")),
      matched_ips:   r.get("matched_ips"),
    }));
  } finally {
    await session.close();
  }

  if (!campaignMatches.length) return { alerts: [], matched_campaigns: [] };

  // ── Step 3: For each new campaign match, fire an alert ───────────────────
  const newAlerts = [];

  for (const match of campaignMatches) {
    const campId = match.campaign_id || match.campaign_name;

    // Redis SISMEMBER — skip if already active (no duplicate alerts)
    const alreadyActive = await redis.sIsMember("campaign:active", campId);
    if (alreadyActive) continue;

    // Mark as active in Redis Set
    await redis.sAdd("campaign:active", campId);

    // Write persistent alert to MongoDB
    const alert = await Alert.create({
      type:        "campaign_match",
      severity:    "critical",
      title:       `Campaign detected: ${match.campaign_name}`,
      description: `${match.matched_count} known IOCs matched to campaign operated by ${match.actor_name}`,
      campaign_id: campId,
      meta:        match,
    });

    // Publish to Redis pub/sub for live dashboard push
    await redis.publish(
      "alert:stream",
      JSON.stringify({
        alert_id:      alert._id,
        type:          "campaign_match",
        severity:      "critical",
        campaign_name: match.campaign_name,
        actor_name:    match.actor_name,
        matched_count: match.matched_count,
        matched_ips:   match.matched_ips,
        timestamp:     new Date().toISOString(),
      })
    );

    newAlerts.push(alert);
  }

  return {
    alerts:            newAlerts,
    matched_campaigns: campaignMatches,
    top_iocs_checked:  ipList.length,
  };
};

// Get all alerts from MongoDB (persistent history)
const getAlerts = async (limit = 50) => {
  return Alert.find().sort({ createdAt: -1 }).limit(limit).lean();
};

// Get currently active campaigns from Redis
const getActiveCampaigns = async () => {
  const redis = getRedis();
  return redis.sMembers("campaign:active");
};

module.exports = { runCorrelation, getAlerts, getActiveCampaigns };
