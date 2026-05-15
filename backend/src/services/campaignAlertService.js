// ── FIXED: neo4j require moved to TOP (was at bottom, after module.exports → ReferenceError)
const neo4j = require("neo4j-driver");
const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");
const Alert = require("../models/Alert");
const Campaign = require("../models/Campaign");
 
const toNum = (val) =>
  val && typeof val === "object" && "low" in val ? val.low : Number(val);
 
// Core correlation: read hot IOCs from Redis → check campaign membership in Neo4j AND MongoDB
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
      message: "No IOCs found in Redis. Please fetch live threat data or ingest some IOCs first.",
    };
  }
 
  const iocList = topIocs.map((i) => i.value);
  console.log(`Campaign Correlation: Checking IOCs: ${iocList.slice(0, 5).join(", ")}...`);
 
  // Strategy 1: Check Neo4j graph for campaign relationships
  const neo4jMatches = await correlateViaGraph(iocList, thresholdInt);
 
  // Strategy 2: Check MongoDB campaigns for IOC matches
  const mongoMatches = await correlateViaMongoDB(iocList, thresholdInt);
 
  // Merge and deduplicate matches
  const allMatches = mergeMatches(neo4jMatches, mongoMatches);
 
  console.log(`Campaign Correlation: Found ${allMatches.length} campaign matches total`);
 
  if (!allMatches.length) {
    return {
      alerts: [],
      matched_campaigns: [],
      top_iocs_checked: iocList.length,
      message: "No campaigns matched the IOCs. Try fetching more live threat data or lowering the threshold.",
    };
  }
 
  const newAlerts = [];
 
  for (const match of allMatches) {
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
      severity: match.severity || "critical",
      title: `Campaign detected: ${match.campaign_name}`,
      description: `${match.matched_count} known IOCs matched to campaign${match.actor_name ? ` operated by ${match.actor_name}` : ""}`,
      campaign_id: campId,
      meta: match,
    });
 
    console.log(`Campaign Correlation: Alert created with ID ${alert._id}`);
 
    const alertPayload = JSON.stringify({
      alert_id: alert._id,
      type: "campaign_match",
      severity: match.severity || "critical",
      campaign_name: match.campaign_name,
      actor_name: match.actor_name,
      matched_count: match.matched_count,
      matched_ips: match.matched_ips || match.matched_iocs,
      timestamp: new Date().toISOString(),
    });
 
    const publishResult = await redis.publish("alert:stream", alertPayload);
    console.log(`Campaign Correlation: Published to ${publishResult} subscribers`);
 
    newAlerts.push(alert);
  }
 
  console.log(`Campaign Correlation: Completed - ${newAlerts.length} new alerts created`);
 
  return {
    alerts: newAlerts,
    matched_campaigns: allMatches,
    top_iocs_checked: iocList.length,
  };
};
 
// Correlate IOCs via Neo4j graph relationships
const correlateViaGraph = async (iocList, threshold) => {
  const session = getNeo4jSession();
  let campaignMatches = [];
 
  try {
    // Query 1: Original path (IP → Domain → Malware → Campaign)
    const cypher1 = `
      MATCH (i:IP)-[:RESOLVES_TO]->(d:Domain)-[:HOSTS]->(m:Malware)-[:USED_BY]->(c:Campaign)
      WHERE i.value IN $iocList
      WITH c, COLLECT(DISTINCT i.value) AS matchedIPs, COUNT(DISTINCT i) AS matchCount
      WHERE matchCount >= $threshold
      OPTIONAL MATCH (c)-[:OPERATED_BY]->(a:ThreatActor)
      RETURN
        c.name         AS campaign_name,
        c.campaign_id  AS campaign_id,
        a.name         AS actor_name,
        matchCount     AS matched_count,
        matchedIPs     AS matched_ips,
        c.severity     AS severity
      ORDER BY matchCount DESC
    `;
 
    // Query 2: Direct associations from live data (IP/Domain → Campaign)
    const cypher2 = `
      MATCH (n)-[:ASSOCIATED_WITH]->(c:Campaign)
      WHERE n.value IN $iocList AND (n:IP OR n:Domain OR n:Hash)
      WITH c, COLLECT(DISTINCT n.value) AS matchedIOCs, COUNT(DISTINCT n) AS matchCount
      WHERE matchCount >= $threshold
      OPTIONAL MATCH (c)-[:OPERATED_BY]->(a:ThreatActor)
      RETURN
        c.name         AS campaign_name,
        c.campaign_id  AS campaign_id,
        a.name         AS actor_name,
        matchCount     AS matched_count,
        matchedIOCs    AS matched_ips,
        c.severity     AS severity
      ORDER BY matchCount DESC
    `;
 
    console.log("Campaign Correlation: Running Neo4j queries...");
 
    const [result1, result2] = await Promise.all([
      session.run(cypher1, { iocList, threshold: neo4j.int(threshold) }),
      session.run(cypher2, { iocList, threshold: neo4j.int(threshold) }),
    ]);
 
    const processRecords = (records) =>
      records.map((r) => ({
        campaign_name: r.get("campaign_name"),
        campaign_id: r.get("campaign_id"),
        actor_name: r.get("actor_name"),
        matched_count: toNum(r.get("matched_count")),
        matched_ips: r.get("matched_ips"),
        severity: r.get("severity") || "critical",
        source: "neo4j",
      }));
 
    campaignMatches = [
      ...processRecords(result1.records),
      ...processRecords(result2.records),
    ];
 
    console.log(`Campaign Correlation: Neo4j returned ${campaignMatches.length} campaign matches`);
 
  } catch (neo4jError) {
    console.error("Campaign Correlation: Neo4j query error:", neo4jError.message);
    // Don't throw - we can still try MongoDB
  } finally {
    await session.close();
  }
 
  return campaignMatches;
};
 
// Correlate IOCs via MongoDB campaign documents
const correlateViaMongoDB = async (iocList, threshold) => {
  const campaignMatches = [];
 
  try {
    // Find campaigns where IOCs match
    const campaigns = await Campaign.find({
      $or: [
        { "iocs.ips": { $in: iocList } },
        { "iocs.domains": { $in: iocList } },
        { "iocs.hashes": { $in: iocList } },
        { "iocs.urls": { $in: iocList } },
      ],
    }).lean();
 
    console.log(`Campaign Correlation: MongoDB found ${campaigns.length} potential campaigns`);
 
    for (const campaign of campaigns) {
      const matchedIocs = [];
 
      // Check which IOCs match
      for (const ioc of iocList) {
        if (
          campaign.iocs.ips?.includes(ioc) ||
          campaign.iocs.domains?.includes(ioc) ||
          campaign.iocs.hashes?.includes(ioc) ||
          campaign.iocs.urls?.includes(ioc)
        ) {
          matchedIocs.push(ioc);
        }
      }
 
      if (matchedIocs.length >= threshold) {
        campaignMatches.push({
          campaign_name: campaign.name,
          campaign_id: campaign.campaign_id,
          actor_name: campaign.threat_actor,
          matched_count: matchedIocs.length,
          matched_ips: matchedIocs,
          matched_iocs: matchedIocs,
          severity: campaign.severity,
          source: "mongodb",
        });
      }
    }
 
    console.log(`Campaign Correlation: MongoDB matched ${campaignMatches.length} campaigns above threshold`);
 
  } catch (mongoError) {
    console.error("Campaign Correlation: MongoDB query error:", mongoError.message);
  }
 
  return campaignMatches;
};
 
// Merge and deduplicate matches from different sources
const mergeMatches = (neo4jMatches, mongoMatches) => {
  const seen = new Set();
  const merged = [];
 
  for (const match of [...neo4jMatches, ...mongoMatches]) {
    const key = match.campaign_id || match.campaign_name;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(match);
    }
  }
 
  // Sort by matched count descending
  merged.sort((a, b) => b.matched_count - a.matched_count);
 
  return merged;
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
 
// Clear active campaigns (for testing/reset)
const clearActiveCampaigns = async () => {
  const redis = getRedis();
  const members = await redis.sMembers("campaign:active");
  if (members.length > 0) {
    await redis.sRem("campaign:active", members);
  }
  return { cleared: members.length };
};
 
// Get correlation statistics
const getCorrelationStats = async () => {
  const redis = getRedis();
 
  const [hotIocsCount, activeCampaigns, alertsCount] = await Promise.all([
    redis.zCard("hot:iocs"),
    redis.sMembers("campaign:active"),
    Alert.countDocuments({ type: "campaign_match" }),
  ]);
 
  const campaignsInDb = await Campaign.countDocuments();
 
  return {
    hot_iocs_count: hotIocsCount,
    active_campaigns: activeCampaigns,
    total_alerts: alertsCount,
    campaigns_in_db: campaignsInDb,
  };
};
 
module.exports = {
  runCorrelation,
  getAlerts,
  getActiveCampaigns,
  clearActiveCampaigns,
  getCorrelationStats,
};
 
 