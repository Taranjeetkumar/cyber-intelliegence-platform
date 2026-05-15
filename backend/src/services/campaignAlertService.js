// ── FIXED: neo4j require moved to TOP (was at bottom, after module.exports → ReferenceError)
const neo4j = require("neo4j-driver");
const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");
const Alert = require("../models/Alert");

const toNum = (val) =>
  val && typeof val === "object" && "low" in val ? val.low : Number(val);

// Core correlation: read hot IOCs from Redis → check campaign membership in Neo4j
const runCorrelation = async (topN = 20, threshold = 2) => {
  const topNInt = parseInt(topN, 10) || 20;
  const thresholdInt = parseInt(threshold, 10) || 2;

  console.log(`Campaign Correlation: Starting with topN=${topNInt}, threshold=${thresholdInt}`);

  const redis = getRedis();

  const topIocs = await redis.zRangeWithScores("hot:iocs", 0, topNInt - 1, { REV: true });

  console.log(`Campaign Correlation: Found ${topIocs.length} IOCs in Redis hot:iocs`);

  if (!topIocs.length) {
    return {
      alerts: [],
      matched_campaigns: [],
      top_iocs_checked: 0,
      message: "No IOCs found in Redis. Please ingest some IOCs first using the IOC Ingest feature.",
    };
  }

  const ipList = topIocs.map((i) => i.value);
  console.log(`Campaign Correlation: Checking IPs: ${ipList.join(", ")}`);

  const session = getNeo4jSession();
  let campaignMatches = [];

  try {
    // ── FIXED: Cypher now follows the actual seeded graph relationships:
    //   IP -[:RESOLVES_TO]-> Domain -[:HOSTS]-> Malware -[:USED_BY]-> Campaign -[:OPERATED_BY]-> ThreatActor
    // The original query used a single hop IP→Malware which doesn't exist in the graph.
    const cypher = `
      MATCH (i:IP)-[:RESOLVES_TO]->(d:Domain)-[:HOSTS]->(m:Malware)-[:USED_BY]->(c:Campaign)
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

    console.log("Campaign Correlation: Running Neo4j query...");

    const result = await session.run(cypher, {
      ipList,
      threshold: neo4j.int(thresholdInt),
    });

    console.log(`Campaign Correlation: Neo4j returned ${result.records.length} campaign matches`);

    campaignMatches = result.records.map((r) => ({
      campaign_name: r.get("campaign_name"),
      campaign_id: r.get("campaign_id"),
      actor_name: r.get("actor_name"),
      matched_count: toNum(r.get("matched_count")),
      matched_ips: r.get("matched_ips"),
    }));
  } catch (neo4jError) {
    console.error("Campaign Correlation: Neo4j query error:", neo4jError.message);
    throw new Error(`Neo4j query failed: ${neo4jError.message}`);
  } finally {
    await session.close();
  }

  if (!campaignMatches.length) {
    return {
      alerts: [],
      matched_campaigns: [],
      top_iocs_checked: ipList.length,
      message: "No campaigns matched the IOCs. This could mean the IOCs are not associated with known campaigns in the graph database.",
    };
  }

  const newAlerts = [];

  for (const match of campaignMatches) {
    const campId = match.campaign_id || match.campaign_name;

    const alreadyActive = await redis.sIsMember("campaign:active", campId);
    if (alreadyActive) {
      console.log(`Campaign Correlation: Campaign ${campId} already active, skipping alert`);
      continue;
    }

    console.log(`Campaign Correlation: New campaign detected - ${match.campaign_name}`);

    await redis.sAdd("campaign:active", campId);

    const alert = await Alert.create({
      type: "campaign_match",
      severity: "critical",
      title: `Campaign detected: ${match.campaign_name}`,
      description: `${match.matched_count} known IOCs matched to campaign operated by ${match.actor_name}`,
      campaign_id: campId,
      meta: match,
    });

    console.log(`Campaign Correlation: Alert created with ID ${alert._id}`);

    const alertPayload = JSON.stringify({
      alert_id: alert._id,
      type: "campaign_match",
      severity: "critical",
      campaign_name: match.campaign_name,
      actor_name: match.actor_name,
      matched_count: match.matched_count,
      matched_ips: match.matched_ips,
      timestamp: new Date().toISOString(),
    });

    const publishResult = await redis.publish("alert:stream", alertPayload);
    console.log(`Campaign Correlation: Published to ${publishResult} subscribers`);

    newAlerts.push(alert);
  }

  console.log(`Campaign Correlation: Completed - ${newAlerts.length} new alerts created`);

  return {
    alerts: newAlerts,
    matched_campaigns: campaignMatches,
    top_iocs_checked: ipList.length,
  };
};

// Get all alerts from MongoDB
const getAlerts = async (limit = 50) => {
  const limitInt = parseInt(limit, 10) || 50;
  return Alert.find().sort({ createdAt: -1 }).limit(limitInt).lean();
};

// Get currently active campaigns from Redis
const getActiveCampaigns = async () => {
  const redis = getRedis();
  return redis.sMembers("campaign:active");
};

module.exports = { runCorrelation, getAlerts, getActiveCampaigns };