// ── In-memory Neo4j mock ──────────────────────────────────────────────────────
class MockNeo4jSession {
  constructor() {
    this.nodes = new Map();   // key → { label, props }
    this.rels  = [];
  }

  async run(cypher, params = {}) {
    // DETACH DELETE — wipe everything
    if (cypher.includes("DETACH DELETE")) {
      this.nodes.clear(); this.rels = [];
      return { records: [] };
    }

    // MERGE node:  MERGE (x:Label {key:'val'}) SET ...
    const mergeNode = cypher.match(/MERGE\s*\(\w+:(\w+)\s*\{([^}]+)\}\)/);
    if (mergeNode && !cypher.includes("MATCH")) {
      const [, label, propsStr] = mergeNode;
      const pk = propsStr.replace(/\s/g, "");
      if (!this.nodes.has(pk)) this.nodes.set(pk, { label, props: this._parseProps(propsStr) });
      const setM = cypher.match(/SET\s+(.+)$/s);
      if (setM) Object.assign(this.nodes.get(pk).props, this._parseSet(setM[1]));
      return { records: [] };
    }

    // MATCH … MERGE relationship
    if (cypher.includes("MERGE") && cypher.includes("MATCH")) {
      this.rels.push(cypher.trim().slice(0, 120));
      return { records: [] };
    }

    // Campaign correlation query
    if (cypher.includes("Campaign") || (cypher.includes("RESOLVES_TO") && cypher.includes("HOSTS"))) {
      return this._campaignQuery(params);
    }

    return { records: [] };
  }

  _parseProps(str) {
    const o = {};
    str.split(",").forEach(p => {
      const [k, v] = p.split(":").map(s => s.trim());
      o[k] = v ? v.replace(/'/g, "") : null;
    });
    return o;
  }

  _parseSet(str) {
    const o = {};
    str.split(",").forEach(p => {
      const eq = p.indexOf("="); if (eq === -1) return;
      const k = p.slice(0, eq).trim().replace(/^\w+\./, "");
      const v = p.slice(eq + 1).trim().replace(/'/g, "");
      o[k] = isNaN(v) ? v : Number(v);
    });
    return o;
  }

  // Simulate the campaign correlation Cypher result
  _campaignQuery(params) {
    const ipList = params.ipList || [];
    const threshold = params.threshold?.low ?? params.threshold ?? 2;

    const graph = [
      { ip: "203.0.113.47",   campaign: "APT29_NOBELIUM",  campaign_id: "APT29_NOBELIUM",  actor: "APT29"   },
      { ip: "198.51.100.23",  campaign: "TA505_Q4_2023",   campaign_id: "TA505_Q4_2023",   actor: "TA505"   },
      { ip: "10.99.88.77",    campaign: "LOCKBIT_WAVE_23", campaign_id: "LOCKBIT_WAVE_23", actor: "LockBit" },
      { ip: "evil-cdn.net",   campaign: "APT29_NOBELIUM",  campaign_id: "APT29_NOBELIUM",  actor: "APT29"   },
      { ip: "phishing-kit.ru",campaign: "TA505_Q4_2023",   campaign_id: "TA505_Q4_2023",   actor: "TA505"   },
      { ip: "malware-drop.xyz",campaign:"LOCKBIT_WAVE_23", campaign_id: "LOCKBIT_WAVE_23", actor: "LockBit" },
    ];

    // Group by campaign, count distinct matching IPs
    const bycamp = new Map();
    for (const row of graph) {
      if (!ipList.includes(row.ip)) continue;
      if (!bycamp.has(row.campaign)) bycamp.set(row.campaign, { campaign_id: row.campaign_id, actor: row.actor, ips: [] });
      bycamp.get(row.campaign).ips.push(row.ip);
    }

    const records = [];
    for (const [name, data] of bycamp) {
      if (data.ips.length >= threshold) {
        records.push(new MockRecord({
          campaign_name:  name,
          campaign_id:    data.campaign_id,
          actor_name:     data.actor,
          matched_count:  { low: data.ips.length, high: 0 },
          matched_ips:    data.ips,
        }));
      }
    }
    return { records };
  }

  async close() {}
}

class MockRecord {
  constructor(d) { this._d = d; }
  get(k) { return this._d[k]; }
}

class MockNeo4jDriver {
  constructor() { this._session = new MockNeo4jSession(); }
  async verifyConnectivity() { return true; }
  session() { return this._session; }
  async close() {}
}

// ── Real Neo4j driver ─────────────────────────────────────────────────────────
const neo4j = require("neo4j-driver");

let driver     = null;
let usingMock  = false;

const connectNeo4j = async () => {
  const uri  = process.env.NEO4J_URI      || "bolt://localhost:7687";
  const user = process.env.NEO4J_USER     || "neo4j";
  const pass = process.env.NEO4J_PASSWORD || "cti_password123";

  try {
    const realDriver = neo4j.driver(uri, neo4j.auth.basic(user, pass),
      { connectionTimeout: 4000 });
    await realDriver.verifyConnectivity();
    driver = realDriver;
    console.log("Neo4j connected (real)");
  } catch (err) {
    console.warn(`Neo4j unavailable (${err.message}) — switching to in-memory mock`);
    usingMock = true;
    driver    = new MockNeo4jDriver();
  }
};

const getNeo4jSession = () => {
  if (!driver) throw new Error("Neo4j not initialised");
  return driver.session({ database: "neo4j" });
};

const closeNeo4j = async () => {
  if (driver) await driver.close();
};

module.exports = { connectNeo4j, getNeo4jSession, closeNeo4j };