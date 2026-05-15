const { createClient } = require("redis");

// ── In-memory Redis mock ───────────────────────────────────────────────────────
class InMemoryRedis {
  constructor() { this.store = new Map(); this.sets = new Map(); this.sortedSets = new Map(); this.subscribers = new Map(); this.lists = new Map(); }
  async connect() { return this; }
  async quit() {}
  async disconnect() {}
  on() { return this; }
  duplicate() {
    const d = new InMemoryRedis();
    d.store = this.store; d.sets = this.sets;
    d.sortedSets = this.sortedSets; d.subscribers = this.subscribers; d.lists = this.lists;
    return d;
  }
  async flushDb() { this.store.clear(); this.sets.clear(); this.sortedSets.clear(); this.lists.clear(); }
  async get(k) { return this.store.get(k) ?? null; }
  async set(k, v, opts) {
    this.store.set(k, v);
    if (opts?.EX) setTimeout(() => this.store.delete(k), opts.EX * 1000);
    return "OK";
  }
  async del(k) { return this.store.delete(k) ? 1 : 0; }
  async exists(k) { return this.store.has(k) ? 1 : 0; }
  async incr(k) { const v = parseInt(this.store.get(k) || "0", 10) + 1; this.store.set(k, String(v)); return v; }
  // Sets
  async sAdd(k, ...members) {
    if (!this.sets.has(k)) this.sets.set(k, new Set());
    const s = this.sets.get(k); let added = 0;
    for (const m of members.flat()) { if (!s.has(m)) { s.add(m); added++; } }
    return added;
  }
  async sMembers(k) { return Array.from(this.sets.get(k) || []); }
  async sIsMember(k, m) { return !!(this.sets.get(k)?.has(m)); }
  async sRem(k, ...members) {
    const s = this.sets.get(k); if (!s) return 0;
    let n = 0; for (const m of members.flat()) { if (s.delete(m)) n++; } return n;
  }
  // Sorted sets
  async zAdd(k, items) {
    if (!this.sortedSets.has(k)) this.sortedSets.set(k, new Map());
    const z = this.sortedSets.get(k); let added = 0;
    for (const { score, value } of (Array.isArray(items) ? items : [])) {
      if (!z.has(value)) added++; z.set(value, score);
    }
    return added;
  }
  async zIncrBy(k, inc, member) {
    if (!this.sortedSets.has(k)) this.sortedSets.set(k, new Map());
    const z = this.sortedSets.get(k);
    const s = (z.get(member) || 0) + inc; z.set(member, s); return s;
  }
  async zRangeWithScores(k, start, stop, opts = {}) {
    const z = this.sortedSets.get(k); if (!z) return [];
    let entries = [...z.entries()].map(([value, score]) => ({ value, score }));
    entries.sort((a, b) => opts.REV ? b.score - a.score : a.score - b.score);
    const len = entries.length;
    const s = start < 0 ? Math.max(0, len + start) : start;
    const e = stop  < 0 ? len + stop + 1 : stop + 1;
    return entries.slice(s, e);
  }
  async zRange(k, start, stop, opts = {}) { return (await this.zRangeWithScores(k, start, stop, opts)).map(i => i.value); }
  async zScore(k, m) { return this.sortedSets.get(k)?.get(m) ?? null; }
  async zCard(k) { return this.sortedSets.get(k)?.size ?? 0; }
  // Lists
  async lPush(k, ...values) {
    if (!this.lists.has(k)) this.lists.set(k, []);
    const l = this.lists.get(k); for (const v of values.flat()) l.unshift(v); return l.length;
  }
  async lTrim(k, start, stop) {
    const l = this.lists.get(k); if (!l) return "OK";
    this.lists.set(k, l.slice(start, stop + 1)); return "OK";
  }
  async lRange(k, start, stop) {
    const l = this.lists.get(k); if (!l) return [];
    return l.slice(start, stop === -1 ? undefined : stop + 1);
  }
  async lLen(k) { return this.lists.get(k)?.length ?? 0; }
  // Hashes
  async hSet(k, field, value) {
    if (!this.store.has(k)) this.store.set(k, new Map());
    this.store.get(k).set(field, value); return 1;
  }
  async hGet(k, f) { return this.store.get(k)?.get(f) ?? null; }
  async hGetAll(k) { const h = this.store.get(k); return h ? Object.fromEntries(h) : {}; }
  // Pub/Sub
  async subscribe(channel, cb) {
    if (!this.subscribers.has(channel)) this.subscribers.set(channel, new Set());
    this.subscribers.get(channel).add(cb);
    // Store cb on this instance so unsubscribe only removes this specific listener
    if (!this._myCbs) this._myCbs = new Map();
    if (!this._myCbs.has(channel)) this._myCbs.set(channel, new Set());
    this._myCbs.get(channel).add(cb);
  }
  async unsubscribe(channel) {
    // Only remove callbacks registered by THIS duplicate, not all subscribers
    const myCbs = this._myCbs?.get(channel);
    if (!myCbs) return;
    const shared = this.subscribers.get(channel);
    if (shared) { for (const cb of myCbs) shared.delete(cb); if (shared.size === 0) this.subscribers.delete(channel); }
    this._myCbs.delete(channel);
  }
  async publish(channel, message) {
    const subs = this.subscribers.get(channel); if (!subs) return 0;
    for (const cb of subs) { try { cb(message, channel); } catch (e) { console.error("pub/sub error:", e); } }
    return subs.size;
  }
}

// ── Connection logic: try real Redis, fall back to mock ───────────────────────
let redisClient = null;
let usingMock   = false;

const connectRedis = async () => {
  const url = process.env.REDIS_URL || "redis://localhost:6379";
  try {
    const client = createClient({ url, socket: { connectTimeout: 4000 } });
    client.on("error", () => {}); // suppress async errors during probe
    await client.connect();
    redisClient = client;
    console.log("Redis connected (real)");

    // Pre-seed hot:iocs only if empty (first run)
    const card = await redisClient.zCard("hot:iocs");
    if (card === 0) {
      await redisClient.zAdd("hot:iocs", [
        { score: 47, value: "203.0.113.47"   },
        { score: 31, value: "198.51.100.23"  },
        { score: 22, value: "10.99.88.77"    },
        { score: 18, value: "phishing-kit.ru"},
        { score: 9,  value: "evil-cdn.net"   },
        { score: 5,  value: "malware-drop.xyz"},
      ]);
      console.log("Redis: pre-seeded hot:iocs");
    }
  } catch (err) {
    console.warn(`Redis unavailable (${err.message}) — switching to in-memory mock`);
    usingMock   = true;
    redisClient = new InMemoryRedis();
    await redisClient.connect();
    // Pre-seed the mock so correlation has data to work with
    await redisClient.zAdd("hot:iocs", [
      { score: 47, value: "203.0.113.47"   },
      { score: 31, value: "198.51.100.23"  },
      { score: 22, value: "10.99.88.77"    },
      { score: 18, value: "phishing-kit.ru"},
      { score: 9,  value: "evil-cdn.net"   },
      { score: 5,  value: "malware-drop.xyz"},
    ]);
    await redisClient.set("risk:host:DESKTOP-HR-01",  "91", { EX: 3600 });
    await redisClient.set("risk:host:SRV-FILE-02",    "76", { EX: 3600 });
    await redisClient.set("risk:host:WS-FINANCE-03",  "84", { EX: 3600 });
    await redisClient.set("stats:ingested:ip",     "4");
    await redisClient.set("stats:ingested:domain", "3");
    await redisClient.set("stats:ingested:hash",   "1");
    await redisClient.set("stats:ingested:url",    "0");
    // Seed active campaigns so the sidebar panel shows data on first load
    await redisClient.sAdd("campaign:active", "APT29_NOBELIUM", "TA505_Q4_2023", "LOCKBIT_WAVE_23");
    console.log("Redis mock: pre-seeded with IOC scores, device risk data, and active campaigns");
  }
};

const getRedis = () => {
  if (!redisClient) throw new Error("Redis not initialised");
  return redisClient;
};

// Returns a fresh unconnected duplicate — SSE handler must call .connect() on it
const createSubscriber = () => {
  if (!redisClient) throw new Error("Redis not initialised");
  return redisClient.duplicate();
};

module.exports = { connectRedis, getRedis, createSubscriber };