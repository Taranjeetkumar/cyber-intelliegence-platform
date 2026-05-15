// ── FIXED: neo4j require moved to TOP (was at bottom, after module.exports → ReferenceError)
const neo4j = require("neo4j-driver");
const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");
const Alert = require("../models/Alert");
const IOC = require("../models/IOC");
const { checkIpReputation, getBlacklistedIps } = require("./abuseIpDbService");
const { checkIpThreatIntel, getSubscribedPulseIndicators } = require("./otxService");

const toNum = (val) =>
  val && typeof val === "object" && "low" in val ? val.low : Number(val);

const isPublicIpv4 = (value) => {
  const parts = String(value).split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }

  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;

  return true;
};

const syncLiveAbuseIntel = async (iocValues) => {
  const publicIps = [...new Set(iocValues.filter(isPublicIpv4))];
  if (!publicIps.length) return [];

  const session = getNeo4jSession();
  const intel = [];

  try {
    for (const ip of publicIps) {
      const reputation = await checkIpReputation(ip);
      const data = reputation.data;

      if (!data) {
        intel.push({
          value: ip,
          source: "abuseipdb",
          configured: reputation.configured,
          error: reputation.error || "No AbuseIPDB data returned",
        });
        continue;
      }

      const abuseScore = Number(data.abuseConfidenceScore || 0);
      const totalReports = Number(data.totalReports || 0);
      const now = new Date();

      await IOC.findOneAndUpdate(
        { value: ip, type: "ip" },
        {
          $set: {
            last_seen: now,
            source: "abuseipdb-live",
            confidence: Math.max(abuseScore, 50),
            "enrichment.whois_country": data.countryCode,
            "enrichment.isp": data.isp,
            "enrichment.usage_type": data.usageType,
            "enrichment.abuseipdb_score": abuseScore,
            "enrichment.abuseipdb_reports": totalReports,
            "enrichment.abuseipdb_last_reported": data.lastReportedAt,
          },
          $addToSet: { tags: { $each: ["live-intel", "abuseipdb"] } },
          $setOnInsert: { first_seen: now },
        },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );

      await session.run(
        `
        MERGE (i:IP {value: $ip})
        SET i.abuseScore = $abuseScore,
            i.totalReports = $totalReports,
            i.country = $country,
            i.isp = $isp,
            i.usageType = $usageType,
            i.lastReportedAt = $lastReportedAt,
            i.last_seen = $ts
        RETURN i
        `,
        {
          ip,
          abuseScore,
          totalReports,
          country: data.countryCode || "",
          isp: data.isp || "",
          usageType: data.usageType || "",
          lastReportedAt: data.lastReportedAt || "",
          ts: now.toISOString(),
        }
      );

      intel.push({
        value: ip,
        source: "abuseipdb",
        configured: true,
        abuse_score: abuseScore,
        total_reports: totalReports,
        country: data.countryCode,
        isp: data.isp,
        usage_type: data.usageType,
        last_reported: data.lastReportedAt,
      });
    }
  } finally {
    await session.close();
  }

  return intel;
};

const syncLiveOtxIntel = async (iocValues) => {
  const publicIps = [...new Set(iocValues.filter(isPublicIpv4))];
  if (!publicIps.length) return [];

  const session = getNeo4jSession();
  const intel = [];

  try {
    for (const ip of publicIps) {
      const otx = await checkIpThreatIntel(ip);
      const pulseInfo = otx.general?.pulse_info;
      const pulseCount = Number(pulseInfo?.count || 0);
      const reputation = Number(otx.reputation?.reputation ?? otx.general?.reputation ?? 0) || 0;

      if (!otx.general && !otx.reputation) {
        intel.push({
          value: ip,
          source: "otx",
          configured: otx.configured,
          error: otx.errors?.join("; ") || "No OTX data returned",
        });
        continue;
      }

      const now = new Date();
      const pulses = Array.isArray(pulseInfo?.pulses) ? pulseInfo.pulses.slice(0, 5) : [];

      await IOC.findOneAndUpdate(
        { value: ip, type: "ip" },
        {
          $set: {
            last_seen: now,
            "enrichment.otx_reputation": reputation,
            "enrichment.otx_pulse_count": pulseCount,
            "enrichment.otx_sections": otx.general?.sections,
            "enrichment.otx_pulses": pulses.map((pulse) => ({
              id: pulse.id,
              name: pulse.name,
              modified: pulse.modified,
            })),
          },
          $addToSet: { tags: { $each: ["live-intel", "otx"] } },
          $setOnInsert: { first_seen: now, source: "otx-live", confidence: Math.min(100, Math.max(50, reputation || pulseCount * 10)) },
        },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );

      await session.run(
        `
        MERGE (i:IP {value: $ip})
        SET i.otxReputation = $reputation,
            i.otxPulseCount = $pulseCount,
            i.otxSections = $sections,
            i.last_seen = $ts
        RETURN i
        `,
        {
          ip,
          reputation,
          pulseCount,
          sections: Array.isArray(otx.general?.sections) ? otx.general.sections.join(", ") : "",
          ts: now.toISOString(),
        }
      );

      intel.push({
        value: ip,
        source: "otx",
        configured: otx.configured,
        reputation,
        pulse_count: pulseCount,
        pulses: pulses.map((pulse) => ({
          id: pulse.id,
          name: pulse.name,
          modified: pulse.modified,
        })),
      });
    }
  } finally {
    await session.close();
  }

  return intel;
};

const buildLiveIntelCampaignMatches = (liveIntel) => {
  const threshold = Number(process.env.CAMPAIGN_ABUSEIPDB_SCORE_THRESHOLD || 75);
  const highRisk = liveIntel.filter((item) => Number(item.abuse_score || 0) >= threshold);

  if (!highRisk.length) return [];

  return [
    {
      campaign_name: "LIVE_ABUSEIPDB_HIGH_RISK",
      campaign_id: "LIVE_ABUSEIPDB_HIGH_RISK",
      actor_name: "Live AbuseIPDB intelligence",
      matched_count: highRisk.length,
      matched_ips: highRisk.map((item) => item.value),
      source: "abuseipdb-live",
      severity: highRisk.some((item) => item.abuse_score >= 90) ? "critical" : "high",
      live_intel: highRisk,
    },
  ];
};

const buildLiveOtxCampaignMatches = (otxIntel) => {
  const minPulses = Number(process.env.CAMPAIGN_OTX_MIN_PULSES || 1);
  const matched = otxIntel.filter((item) => Number(item.pulse_count || 0) >= minPulses);

  if (!matched.length) return [];

  return [
    {
      campaign_name: "LIVE_OTX_PULSE_MATCH",
      campaign_id: "LIVE_OTX_PULSE_MATCH",
      actor_name: "AlienVault OTX pulses",
      matched_count: matched.length,
      matched_ips: matched.map((item) => item.value),
      source: "otx-live",
      severity: matched.some((item) => item.pulse_count >= 3 || item.reputation >= 80) ? "critical" : "high",
      live_intel: matched,
    },
  ];
};

const importLiveAbuseFeed = async ({ limit = 5, confidenceMinimum = 90 } = {}) => {
  const [abuseFeed, otxFeed] = await Promise.all([
    getBlacklistedIps({ limit, confidenceMinimum }),
    getSubscribedPulseIndicators({ limit }),
  ]);

  const redis = getRedis();
  const imported = [];
  const now = new Date();

  for (const item of abuseFeed.data || []) {
    const value = item.ipAddress || item.ip;
    if (!value) continue;

    const abuseScore = Number(item.abuseConfidenceScore || confidenceMinimum || 90);
    const totalReports = Number(item.totalReports || item.numReports || 0);

    await IOC.findOneAndUpdate(
      { value, type: "ip" },
      {
        $set: {
          last_seen: now,
          source: "abuseipdb-blacklist",
          confidence: abuseScore,
          "enrichment.whois_country": item.countryCode,
          "enrichment.abuseipdb_score": abuseScore,
          "enrichment.abuseipdb_reports": totalReports,
          "enrichment.abuseipdb_last_reported": item.lastReportedAt,
        },
        $addToSet: { tags: { $each: ["live-feed", "abuseipdb", "blacklist"] } },
        $setOnInsert: { first_seen: now },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    await redis.zAdd("hot:iocs", [{ score: Math.max(abuseScore, 1), value }]);

    imported.push({
      value,
      source: "abuseipdb-blacklist",
      abuse_score: abuseScore,
      total_reports: totalReports,
      country: item.countryCode,
      last_reported: item.lastReportedAt,
    });
  }

  for (const item of otxFeed.data || []) {
    const value = item.value;
    if (!value) continue;

    await IOC.findOneAndUpdate(
      { value, type: "ip" },
      {
        $set: {
          last_seen: now,
          source: "otx-subscribed-pulse",
          confidence: 80,
          "enrichment.otx_pulse_id": item.pulse_id,
          "enrichment.otx_pulse_name": item.pulse_name,
          "enrichment.otx_adversary": item.adversary,
          "enrichment.otx_modified": item.modified,
        },
        $addToSet: { tags: { $each: ["live-feed", "otx", ...item.tags.slice(0, 8)] } },
        $setOnInsert: { first_seen: now },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    await redis.zAdd("hot:iocs", [{ score: 80, value }]);

    imported.push({
      value,
      source: "otx-subscribed-pulse",
      pulse_name: item.pulse_name,
      adversary: item.adversary,
      tags: item.tags,
      modified: item.modified,
    });
  }

  return {
    configured: Boolean(abuseFeed.configured || otxFeed.configured),
    sources: {
      abuseipdb: {
        configured: abuseFeed.configured,
        error: abuseFeed.error,
      },
      otx: {
        configured: otxFeed.configured,
        error: otxFeed.error,
        pulse_count: otxFeed.pulse_count,
      },
    },
    imported,
    count: imported.length,
    message: imported.length
      ? `${imported.length} live AbuseIPDB/OTX IPs added to Redis hot:iocs`
      : "No live AbuseIPDB blacklist or OTX subscribed-pulse IPs were returned",
  };
};

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

  console.log("Campaign Correlation: Pulling live AbuseIPDB and OTX data for public IPs...");
  const [liveIntel, otxIntel] = await Promise.all([
    syncLiveAbuseIntel(ipList),
    syncLiveOtxIntel(ipList),
  ]);
  console.log(`Campaign Correlation: AbuseIPDB checked ${liveIntel.length} public IPs`);
  console.log(`Campaign Correlation: OTX checked ${otxIntel.length} public IPs`);

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
      source: "neo4j-campaign-graph",
      severity: "critical",
    }));
  } catch (neo4jError) {
    console.error("Campaign Correlation: Neo4j query error:", neo4jError.message);
    throw new Error(`Neo4j query failed: ${neo4jError.message}`);
  } finally {
    await session.close();
  }

  campaignMatches = [
    ...campaignMatches,
    ...buildLiveIntelCampaignMatches(liveIntel),
    ...buildLiveOtxCampaignMatches(otxIntel),
  ];

  if (!campaignMatches.length) {
    return {
      alerts: [],
      matched_campaigns: [],
      top_iocs_checked: ipList.length,
      live_intel: liveIntel,
      otx_intel: otxIntel,
      message: "No campaigns matched the IOCs and no high-risk live AbuseIPDB/OTX indicators were found.",
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
      severity: match.severity || "critical",
      title: `Campaign detected: ${match.campaign_name}`,
      description: `${match.matched_count} known IOCs matched to campaign operated by ${match.actor_name}`,
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
      matched_ips: match.matched_ips,
      source: match.source,
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
    live_intel: liveIntel,
    otx_intel: otxIntel,
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

module.exports = { runCorrelation, getAlerts, getActiveCampaigns, importLiveAbuseFeed };
