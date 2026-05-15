/**
 * Live Threat Intelligence Service
 * Fetches real-time threat data from AlienVault OTX and other sources
 * Stores campaigns, IOCs in MongoDB, Redis, and Neo4j
 */

const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");
const IOC = require("../models/IOC");
const Campaign = require("../models/Campaign");

const OTX_BASE_URL = "https://otx.alienvault.com/api/v1";

// ── OTX API Helpers ────────────────────────────────────────────────────────────

const buildOTXHeaders = () => {
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };

  const apiKey = process.env.OTX_API_KEY;
  if (apiKey) {
    headers["X-OTX-API-KEY"] = apiKey;
  }

  return headers;
};

const fetchWithRetry = async (url, options = {}, retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, {
        ...options,
        headers: { ...buildOTXHeaders(), ...options.headers },
      });

      if (response.status === 429) {
        // Rate limited - wait and retry
        const waitTime = Math.pow(2, i + 1) * 1000;
        console.log(`OTX rate limited, waiting ${waitTime}ms...`);
        await new Promise((r) => setTimeout(r, waitTime));
        continue;
      }

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(`OTX API error: ${response.status} - ${errorBody}`);
      }

      return await response.json();
    } catch (error) {
      if (i === retries - 1) throw error;
      await new Promise((r) => setTimeout(r, 1000 * (i + 1)));
    }
  }
};

// ── Fetch OTX Pulses (Campaigns) ───────────────────────────────────────────────

/**
 * Fetch subscribed pulses from OTX (requires API key)
 */
const fetchOTXSubscribedPulses = async (limit = 50, page = 1) => {
  if (!process.env.OTX_API_KEY) {
    throw new Error("OTX_API_KEY not configured");
  }

  const url = `${OTX_BASE_URL}/pulses/subscribed?limit=${limit}&page=${page}`;
  console.log(`Fetching OTX subscribed pulses: ${url}`);

  const data = await fetchWithRetry(url);
  return data.results || [];
};

/**
 * Fetch recent pulses from OTX (public, no API key required)
 */
const fetchOTXRecentPulses = async (limit = 50, page = 1) => {
  const url = `${OTX_BASE_URL}/pulses/activity?limit=${limit}&page=${page}`;
  console.log(`Fetching OTX recent pulses: ${url}`);

  const data = await fetchWithRetry(url);
  return data.results || [];
};

/**
 * Search OTX pulses by query
 */
const searchOTXPulses = async (query, limit = 20) => {
  const url = `${OTX_BASE_URL}/search/pulses?q=${encodeURIComponent(query)}&limit=${limit}`;
  console.log(`Searching OTX pulses: ${url}`);

  const data = await fetchWithRetry(url);
  return data.results || [];
};

/**
 * Fetch specific pulse details by ID
 */
const fetchOTXPulseDetails = async (pulseId) => {
  const url = `${OTX_BASE_URL}/pulses/${pulseId}`;
  console.log(`Fetching OTX pulse details: ${url}`);

  return await fetchWithRetry(url);
};

/**
 * Fetch IOC indicators for a pulse
 */
const fetchOTXPulseIndicators = async (pulseId) => {
  const url = `${OTX_BASE_URL}/pulses/${pulseId}/indicators`;
  console.log(`Fetching OTX pulse indicators: ${url}`);

  const data = await fetchWithRetry(url);
  return data.results || [];
};

// ── Process and Store Pulses ───────────────────────────────────────────────────

/**
 * Extract IOCs from OTX pulse indicators
 */
const extractIOCsFromIndicators = (indicators) => {
  const iocs = {
    ips: [],
    domains: [],
    urls: [],
    hashes: [],
    emails: [],
  };

  for (const indicator of indicators) {
    const value = indicator.indicator;
    const type = indicator.type;

    switch (type) {
      case "IPv4":
      case "IPv6":
        iocs.ips.push(value);
        break;
      case "domain":
      case "hostname":
        iocs.domains.push(value);
        break;
      case "URL":
      case "URI":
        iocs.urls.push(value);
        break;
      case "FileHash-MD5":
      case "FileHash-SHA1":
      case "FileHash-SHA256":
        iocs.hashes.push(value);
        break;
      case "email":
        iocs.emails.push(value);
        break;
    }
  }

  return iocs;
};

/**
 * Determine severity based on pulse data
 */
const determineSeverity = (pulse) => {
  const tags = (pulse.tags || []).map((t) => t.toLowerCase());
  const name = (pulse.name || "").toLowerCase();
  const description = (pulse.description || "").toLowerCase();
  const combined = [...tags, name, description].join(" ");

  // Critical indicators
  if (
    combined.includes("apt") ||
    combined.includes("ransomware") ||
    combined.includes("zero-day") ||
    combined.includes("0day") ||
    combined.includes("critical")
  ) {
    return "critical";
  }

  // High severity indicators
  if (
    combined.includes("malware") ||
    combined.includes("backdoor") ||
    combined.includes("trojan") ||
    combined.includes("c2") ||
    combined.includes("command and control") ||
    combined.includes("phishing")
  ) {
    return "high";
  }

  // Medium severity indicators
  if (
    combined.includes("suspicious") ||
    combined.includes("exploit") ||
    combined.includes("vulnerability")
  ) {
    return "medium";
  }

  return "low";
};

/**
 * Extract threat actor from pulse data
 */
const extractThreatActor = (pulse) => {
  const tags = pulse.tags || [];
  const name = pulse.name || "";

  // Common APT naming patterns
  const aptPatterns = [
    /APT\d+/gi,
    /TA\d+/gi,
    /FIN\d+/gi,
    /Lazarus/gi,
    /Cozy Bear/gi,
    /Fancy Bear/gi,
    /Turla/gi,
    /Equation Group/gi,
    /Carbanak/gi,
    /Emotet/gi,
    /TrickBot/gi,
    /LockBit/gi,
    /REvil/gi,
    /Conti/gi,
    /DarkSide/gi,
    /Kimsuky/gi,
    /Sandworm/gi,
  ];

  const combined = [name, ...tags].join(" ");

  for (const pattern of aptPatterns) {
    const match = combined.match(pattern);
    if (match) {
      return match[0];
    }
  }

  // Check adversary field
  if (pulse.adversary) {
    return pulse.adversary;
  }

  return null;
};

/**
 * Process and store a single OTX pulse as a campaign
 */
const processAndStorePulse = async (pulse, indicators = []) => {
  const iocs = extractIOCsFromIndicators(indicators);

  const campaignData = {
    campaign_id: `otx_${pulse.id}`,
    name: pulse.name,
    description: pulse.description || "",
    author: pulse.author?.username || pulse.author_name || "unknown",
    threat_actor: extractThreatActor(pulse),
    tags: pulse.tags || [],
    targeted_countries: pulse.targeted_countries || [],
    industries: pulse.industries || [],
    malware_families: pulse.malware_families || [],
    iocs,
    references: pulse.references || [],
    severity: determineSeverity(pulse),
    confidence: 70, // Default confidence for OTX data
    source: "otx",
    source_id: pulse.id,
    source_url: `https://otx.alienvault.com/pulse/${pulse.id}`,
    first_seen: pulse.created ? new Date(pulse.created) : new Date(),
    last_modified: pulse.modified ? new Date(pulse.modified) : new Date(),
    is_active: true,
    adversary: pulse.adversary || null,
    tlp: pulse.tlp || "white",
  };

  // Upsert campaign to MongoDB
  const campaign = await Campaign.findOneAndUpdate(
    { campaign_id: campaignData.campaign_id },
    campaignData,
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

  return campaign;
};

// ── Store IOCs in Databases ────────────────────────────────────────────────────

/**
 * Store IOCs from a campaign into MongoDB, Redis, and Neo4j
 */
const storeIOCsFromCampaign = async (campaign) => {
  const results = {
    mongodb: { success: 0, errors: 0 },
    redis: { success: 0, errors: 0 },
    neo4j: { success: 0, errors: 0 },
  };

  const redis = getRedis();
  const session = getNeo4jSession();

  try {
    // Process IPs
    for (const ip of campaign.iocs.ips || []) {
      try {
        // MongoDB
        await IOC.findOneAndUpdate(
          { value: ip, type: "ip" },
          {
            $set: {
              last_seen: new Date(),
              tags: campaign.tags,
              source: "otx",
              confidence: campaign.confidence,
            },
            $setOnInsert: { first_seen: new Date() },
          },
          { upsert: true, new: true }
        );
        results.mongodb.success++;

        // Redis hot IOCs
        await redis.zIncrBy("hot:iocs", 1, ip);
        results.redis.success++;

        // Neo4j
        await session.run(
          `
          MERGE (i:IP {value: $value})
          ON CREATE SET i.first_seen = $ts, i.source = 'otx', i.confidence = $confidence
          ON MATCH SET i.last_seen = $ts
          `,
          { value: ip, ts: new Date().toISOString(), confidence: campaign.confidence }
        );
        results.neo4j.success++;
      } catch (err) {
        console.error(`Error storing IP ${ip}:`, err.message);
        results.mongodb.errors++;
      }
    }

    // Process Domains
    for (const domain of campaign.iocs.domains || []) {
      try {
        // MongoDB
        await IOC.findOneAndUpdate(
          { value: domain, type: "domain" },
          {
            $set: {
              last_seen: new Date(),
              tags: campaign.tags,
              source: "otx",
              confidence: campaign.confidence,
            },
            $setOnInsert: { first_seen: new Date() },
          },
          { upsert: true, new: true }
        );
        results.mongodb.success++;

        // Redis
        await redis.zIncrBy("hot:iocs", 1, domain);
        results.redis.success++;

        // Neo4j
        await session.run(
          `
          MERGE (d:Domain {value: $value})
          ON CREATE SET d.first_seen = $ts, d.source = 'otx'
          ON MATCH SET d.last_seen = $ts
          `,
          { value: domain, ts: new Date().toISOString() }
        );
        results.neo4j.success++;
      } catch (err) {
        console.error(`Error storing domain ${domain}:`, err.message);
        results.mongodb.errors++;
      }
    }

    // Process Hashes
    for (const hash of campaign.iocs.hashes || []) {
      try {
        // MongoDB
        await IOC.findOneAndUpdate(
          { value: hash, type: "hash" },
          {
            $set: {
              last_seen: new Date(),
              tags: campaign.tags,
              source: "otx",
              confidence: campaign.confidence,
            },
            $setOnInsert: { first_seen: new Date() },
          },
          { upsert: true, new: true }
        );
        results.mongodb.success++;

        // Neo4j
        await session.run(
          `
          MERGE (h:Hash {value: $value})
          ON CREATE SET h.first_seen = $ts, h.source = 'otx'
          ON MATCH SET h.last_seen = $ts
          `,
          { value: hash, ts: new Date().toISOString() }
        );
        results.neo4j.success++;
      } catch (err) {
        console.error(`Error storing hash ${hash}:`, err.message);
        results.mongodb.errors++;
      }
    }

    // Create Campaign and ThreatActor nodes in Neo4j with relationships
    await createCampaignGraph(session, campaign);

  } finally {
    await session.close();
  }

  return results;
};

/**
 * Create campaign graph structure in Neo4j
 */
const createCampaignGraph = async (session, campaign) => {
  // Create Campaign node
  await session.run(
    `
    MERGE (c:Campaign {campaign_id: $campaign_id})
    SET c.name = $name,
        c.description = $description,
        c.severity = $severity,
        c.source = $source,
        c.first_seen = $first_seen,
        c.last_modified = $last_modified
    `,
    {
      campaign_id: campaign.campaign_id,
      name: campaign.name,
      description: campaign.description?.substring(0, 500) || "",
      severity: campaign.severity,
      source: campaign.source,
      first_seen: campaign.first_seen?.toISOString() || new Date().toISOString(),
      last_modified: campaign.last_modified?.toISOString() || new Date().toISOString(),
    }
  );

  // Create ThreatActor if exists
  if (campaign.threat_actor) {
    await session.run(
      `
      MERGE (a:ThreatActor {name: $name})
      SET a.origin = 'otx'
      WITH a
      MATCH (c:Campaign {campaign_id: $campaign_id})
      MERGE (c)-[:OPERATED_BY]->(a)
      `,
      { name: campaign.threat_actor, campaign_id: campaign.campaign_id }
    );
  }

  // Link IPs to Campaign through Domain → Malware pattern
  for (const ip of campaign.iocs.ips || []) {
    await session.run(
      `
      MATCH (i:IP {value: $ip})
      MATCH (c:Campaign {campaign_id: $campaign_id})
      MERGE (i)-[:ASSOCIATED_WITH]->(c)
      `,
      { ip, campaign_id: campaign.campaign_id }
    );
  }

  // Link Domains to Campaign
  for (const domain of campaign.iocs.domains || []) {
    await session.run(
      `
      MATCH (d:Domain {value: $domain})
      MATCH (c:Campaign {campaign_id: $campaign_id})
      MERGE (d)-[:ASSOCIATED_WITH]->(c)
      `,
      { domain, campaign_id: campaign.campaign_id }
    );
  }

  // Create malware nodes from tags and link to campaign
  const malwareKeywords = ["emotet", "trickbot", "lockbit", "ryuk", "revil", "conti", "cobalt strike", "mimikatz"];
  for (const tag of campaign.tags || []) {
    const tagLower = tag.toLowerCase();
    if (malwareKeywords.some((m) => tagLower.includes(m))) {
      await session.run(
        `
        MERGE (m:Malware {name: $name})
        SET m.source = 'otx'
        WITH m
        MATCH (c:Campaign {campaign_id: $campaign_id})
        MERGE (m)-[:USED_BY]->(c)
        `,
        { name: tag, campaign_id: campaign.campaign_id }
      );
    }
  }

  // Link domains to IPs with RESOLVES_TO if both exist in same campaign
  for (const ip of campaign.iocs.ips || []) {
    for (const domain of campaign.iocs.domains || []) {
      await session.run(
        `
        MATCH (i:IP {value: $ip})
        MATCH (d:Domain {value: $domain})
        MERGE (i)-[:RESOLVES_TO]->(d)
        `,
        { ip, domain }
      );
    }
  }
};

// ── Main Fetch Functions ───────────────────────────────────────────────────────

/**
 * Fetch and store live threat intelligence data
 */
const fetchAndStoreLiveThreatIntel = async (options = {}) => {
  const {
    source = "recent", // "recent", "subscribed", or "search"
    query = "",
    limit = 20,
    page = 1,
  } = options;

  console.log(`Fetching live threat intel: source=${source}, limit=${limit}, page=${page}`);

  const stats = {
    pulses_fetched: 0,
    campaigns_stored: 0,
    iocs_stored: { mongodb: 0, redis: 0, neo4j: 0 },
    errors: [],
    timestamp: new Date().toISOString(),
  };

  try {
    // Fetch pulses based on source
    let pulses = [];

    if (source === "subscribed") {
      pulses = await fetchOTXSubscribedPulses(limit, page);
    } else if (source === "search" && query) {
      pulses = await searchOTXPulses(query, limit);
    } else {
      pulses = await fetchOTXRecentPulses(limit, page);
    }

    stats.pulses_fetched = pulses.length;
    console.log(`Fetched ${pulses.length} pulses from OTX`);

    // Process each pulse
    for (const pulse of pulses) {
      try {
        // Fetch full pulse details with indicators
        let indicators = [];
        try {
          indicators = await fetchOTXPulseIndicators(pulse.id);
        } catch (err) {
          console.warn(`Failed to fetch indicators for pulse ${pulse.id}:`, err.message);
          // Use indicators from pulse if available
          indicators = pulse.indicators || [];
        }

        // Store as campaign
        const campaign = await processAndStorePulse(pulse, indicators);
        stats.campaigns_stored++;

        // Store IOCs
        const iocResults = await storeIOCsFromCampaign(campaign);
        stats.iocs_stored.mongodb += iocResults.mongodb.success;
        stats.iocs_stored.redis += iocResults.redis.success;
        stats.iocs_stored.neo4j += iocResults.neo4j.success;

        console.log(`Processed pulse: ${pulse.name} (${indicators.length} indicators)`);

        // Small delay to avoid rate limiting
        await new Promise((r) => setTimeout(r, 200));

      } catch (err) {
        console.error(`Error processing pulse ${pulse.id}:`, err.message);
        stats.errors.push({ pulse_id: pulse.id, error: err.message });
      }
    }

    // Update last fetch timestamp in Redis
    const redis = getRedis();
    await redis.set("threat_intel:last_fetch", new Date().toISOString());
    await redis.set("threat_intel:last_stats", JSON.stringify(stats));

  } catch (err) {
    console.error("Error fetching live threat intel:", err.message);
    stats.errors.push({ error: err.message });
  }

  console.log("Live threat intel fetch complete:", stats);
  return stats;
};

/**
 * Get fetch status and statistics
 */
const getFetchStatus = async () => {
  const redis = getRedis();

  const lastFetch = await redis.get("threat_intel:last_fetch");
  const lastStatsStr = await redis.get("threat_intel:last_stats");
  const lastStats = lastStatsStr ? JSON.parse(lastStatsStr) : null;

  const campaignCount = await Campaign.countDocuments();
  const iocCount = await IOC.countDocuments();

  return {
    last_fetch: lastFetch,
    last_stats: lastStats,
    total_campaigns: campaignCount,
    total_iocs: iocCount,
    otx_configured: Boolean(process.env.OTX_API_KEY),
  };
};

/**
 * Search campaigns by various criteria
 */
const searchCampaigns = async (query = {}) => {
  const {
    keyword,
    threat_actor,
    severity,
    source,
    limit = 50,
  } = query;

  const filter = {};

  if (keyword) {
    filter.$or = [
      { name: { $regex: keyword, $options: "i" } },
      { description: { $regex: keyword, $options: "i" } },
      { tags: { $in: [new RegExp(keyword, "i")] } },
    ];
  }

  if (threat_actor) {
    filter.threat_actor = { $regex: threat_actor, $options: "i" };
  }

  if (severity) {
    filter.severity = severity;
  }

  if (source) {
    filter.source = source;
  }

  return Campaign.find(filter)
    .sort({ last_modified: -1 })
    .limit(parseInt(limit, 10))
    .lean();
};

/**
 * Get campaign details with IOCs
 */
const getCampaignDetails = async (campaignId) => {
  return Campaign.findOne({ campaign_id: campaignId }).lean();
};

module.exports = {
  fetchOTXSubscribedPulses,
  fetchOTXRecentPulses,
  searchOTXPulses,
  fetchOTXPulseDetails,
  fetchOTXPulseIndicators,
  fetchAndStoreLiveThreatIntel,
  getFetchStatus,
  searchCampaigns,
  getCampaignDetails,
  processAndStorePulse,
  storeIOCsFromCampaign,
};
