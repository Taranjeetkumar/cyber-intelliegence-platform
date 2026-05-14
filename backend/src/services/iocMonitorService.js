const { getRedis } = require("../config/redis");
const IOC = require("../models/IOC");

const getLiveLeaderboard = async (limit = 10) => {
  const redis = getRedis();

  const topIocs = await redis.zRangeWithScores("hot:iocs", 0, limit - 1, {
    REV: true,
  });

  if (!topIocs.length) return { leaderboard: [], updatedAt: new Date() };

  const values = topIocs.map((i) => i.value);
  const mongoDocs = await IOC.find(
    { value: { $in: values } },
    { value: 1, type: 1, tags: 1, confidence: 1, "enrichment.whois_country": 1, "enrichment.virustotal_score": 1 }
  ).lean();

  const mongoMap = {};
  mongoDocs.forEach((d) => (mongoMap[d.value] = d));

  const leaderboard = topIocs.map((item, idx) => ({
    rank: idx + 1,
    value: item.value,
    hits: item.score,
    ...(mongoMap[item.value] || {}),
  }));

  return { leaderboard, updatedAt: new Date() };
};

const getDeviceRiskScores = async () => {
  const redis = getRedis();

  const keys = [];
  for await (const key of redis.scanIterator({ MATCH: "risk:host:*", COUNT: 100 })) {
    keys.push(key);
  }

  if (!keys.length) return [];

  const scores = await Promise.all(
    keys.map(async (key) => {
      const score = await redis.get(key);
      const ttl = await redis.ttl(key);
      const hostname = key.replace("risk:host:", "");
      return { hostname, risk_score: parseInt(score), ttl_seconds: ttl };
    })
  );

  return scores.sort((a, b) => b.risk_score - a.risk_score);
};

// Get all currently active campaigns from Redis Set
const getActiveCampaigns = async () => {
  const redis = getRedis();
  const members = await redis.sMembers("campaign:active");
  return members;
};

// Increment IOC hit counter (called by ingestion)
const recordIocHit = async (iocValue) => {
  const redis = getRedis();
  const newScore = await redis.zIncrBy("hot:iocs", 1, iocValue);
  return { value: iocValue, hits: newScore };
};

module.exports = { getLiveLeaderboard, getDeviceRiskScores, getActiveCampaigns, recordIocHit };
