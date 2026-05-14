const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");
const HoneypotEvent = require("../models/HoneypotEvent");
const IOC = require("../models/IOC");
const { checkIpReputation } = require("./abuseIpDbService");
const { checkIpThreatIntel } = require("./otxService");

const sanitizeText = (value, limit = 512) => {
  if (typeof value !== "string") return undefined;
  return value.replace(/[^\x09\x0A\x0D\x20-\x7E]/g, "").slice(0, limit);
};

const isPrivateOrLocalIp = (ip) =>
  ip === "127.0.0.1" ||
  ip === "::1" ||
  ip.startsWith("10.") ||
  ip.startsWith("192.168.") ||
  /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip);

const normalizeEvent = (input = {}) => ({
  sourceIp: sanitizeText(input.sourceIp, 80),
  service: ["ssh", "http", "telnet"].includes(input.service) ? input.service : "unknown",
  protocol: sanitizeText(input.protocol, 16) || "tcp",
  destinationPort: Number(input.destinationPort) || undefined,
  eventType: sanitizeText(input.eventType, 80) || "connection_attempt",
  sensorId: sanitizeText(input.sensorId, 80) || "honeypod",
  severity: ["low", "medium", "high", "critical"].includes(input.severity) ? input.severity : "medium",
  username: sanitizeText(input.username, 120),
  password: sanitizeText(input.password, 120),
  method: sanitizeText(input.method, 16),
  path: sanitizeText(input.path, 240),
  userAgent: sanitizeText(input.userAgent, 240),
  payload: sanitizeText(input.payload, 512),
  capturedAt: input.capturedAt ? new Date(input.capturedAt) : new Date(),
});

const scoreSeverity = (severity) => {
  if (severity === "critical") return 95;
  if (severity === "high") return 85;
  if (severity === "medium") return 65;
  return 40;
};

const buildEnrichment = (abuseIpDb, otx) => ({
  abuseipdb: abuseIpDb?.data
    ? {
        abuseConfidenceScore: abuseIpDb.data.abuseConfidenceScore,
        totalReports: abuseIpDb.data.totalReports,
        countryCode: abuseIpDb.data.countryCode,
        isp: abuseIpDb.data.isp,
        usageType: abuseIpDb.data.usageType,
        lastReportedAt: abuseIpDb.data.lastReportedAt,
      }
    : { error: abuseIpDb?.error, configured: abuseIpDb?.configured },
  otx: {
    configured: otx?.configured,
    pulseCount: otx?.general?.pulse_info?.count || 0,
    reputation: otx?.reputation?.reputation ?? otx?.general?.reputation,
    country: otx?.general?.country_name || otx?.general?.country_code,
    asn: otx?.general?.asn,
    errors: otx?.errors || [],
  },
});

const upsertNeo4jGraph = async (event, enrichment, otx) => {
  const session = getNeo4jSession();
  const pulses = otx?.general?.pulse_info?.pulses || [];

  try {
    await session.run(
      `
      MERGE (ip:IP {value: $sourceIp})
      SET ip.lastSeen = datetime($capturedAt),
          ip.source = 'honeypot',
          ip.confidence = $confidence,
          ip.abuseScore = $abuseScore,
          ip.country = $country,
          ip.asn = $asn
      MERGE (svc:Service {name: $service})
      SET svc.protocol = $protocol,
          svc.port = $destinationPort
      MERGE (ip)-[targeted:TARGETED]->(svc)
      SET targeted.lastSeen = datetime($capturedAt),
          targeted.eventType = $eventType,
          targeted.severity = $severity,
          targeted.count = coalesce(targeted.count, 0) + 1
      WITH ip
      FOREACH (_ IN CASE WHEN $username IS NULL THEN [] ELSE [1] END |
        MERGE (cred:Credential {username: $username, password: $password})
        MERGE (ip)-[:ATTEMPTED_CREDENTIAL]->(cred)
      )
      WITH ip
      UNWIND $pulses AS pulse
      WITH ip, pulse WHERE pulse.name IS NOT NULL
      MERGE (p:Pulse {name: pulse.name})
      SET p.id = pulse.id,
          p.modified = pulse.modified
      MERGE (ip)-[:MENTIONED_IN]->(p)
      `,
      {
        sourceIp: event.sourceIp,
        capturedAt: event.capturedAt.toISOString(),
        service: event.service.toUpperCase(),
        protocol: event.protocol,
        destinationPort: event.destinationPort || 0,
        eventType: event.eventType,
        severity: event.severity,
        confidence: scoreSeverity(event.severity),
        abuseScore: enrichment.abuseipdb?.abuseConfidenceScore || 0,
        country: enrichment.abuseipdb?.countryCode || enrichment.otx?.country || "",
        asn: enrichment.otx?.asn || "",
        username: event.username || null,
        password: event.password || "",
        pulses: pulses.slice(0, 10).map((pulse) => ({
          id: pulse.id || "",
          name: pulse.name || "",
          modified: pulse.modified || "",
        })),
      }
    );
  } finally {
    await session.close();
  }
};

const recordHoneypotEvent = async (input) => {
  const event = normalizeEvent(input);
  if (!event.sourceIp) {
    const error = new Error("sourceIp is required");
    error.status = 400;
    throw error;
  }

  const [abuseIpDb, otx] = isPrivateOrLocalIp(event.sourceIp)
    ? [
        {
          configured: Boolean(process.env.ABUSEIPDB_API_KEY),
          error: "Private/local demo IP skipped for AbuseIPDB lookup",
        },
        {
          configured: Boolean(process.env.OTX_API_KEY),
          general: null,
          reputation: null,
          errors: ["Private/local demo IP skipped for OTX lookup"],
        },
      ]
    : await Promise.all([
        checkIpReputation(event.sourceIp),
        checkIpThreatIntel(event.sourceIp),
      ]);
  const enrichment = buildEnrichment(abuseIpDb, otx);

  const savedEvent = await HoneypotEvent.create({ ...event, enrichment });

  await IOC.findOneAndUpdate(
    { value: event.sourceIp, type: "ip" },
    {
      $set: {
        value: event.sourceIp,
        type: "ip",
        source: "honeypot",
        confidence: Math.max(
          scoreSeverity(event.severity),
          Number(enrichment.abuseipdb?.abuseConfidenceScore || 0)
        ),
        last_seen: event.capturedAt,
        enrichment: {
          whois_country: enrichment.abuseipdb?.countryCode || enrichment.otx?.country,
          asn: enrichment.otx?.asn,
          isp: enrichment.abuseipdb?.isp,
          abuseipdb_score: enrichment.abuseipdb?.abuseConfidenceScore,
          abuseipdb_reports: enrichment.abuseipdb?.totalReports,
          otx_pulse_count: enrichment.otx?.pulseCount,
          targeted_service: event.service,
          last_honeypot_event: event.eventType,
        },
      },
      $addToSet: {
        tags: { $each: ["honeypot", event.service, event.severity] },
      },
      $setOnInsert: {
        first_seen: event.capturedAt,
      },
    },
    { upsert: true, new: true }
  );

  await upsertNeo4jGraph(event, enrichment, otx);

  const redis = getRedis();
  await redis.zIncrBy("hot:iocs", 1, event.sourceIp);
  await redis.lPush("live:honeypot:events", JSON.stringify(savedEvent.toObject()));
  await redis.lTrim("live:honeypot:events", 0, 99);

  return savedEvent;
};

const listRecentHoneypotEvents = async (limit = 25) => {
  const boundedLimit = Math.min(Math.max(Number(limit) || 25, 1), 100);
  return HoneypotEvent.find({})
    .sort({ capturedAt: -1 })
    .limit(boundedLimit)
    .lean();
};

module.exports = { recordHoneypotEvent, listRecentHoneypotEvents };
