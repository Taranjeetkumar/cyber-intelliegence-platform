const mongoose = require("mongoose");
const EventEmitter = require("events");

// ── In-memory MongoDB mock (used when real MongoDB isn't reachable) ────────────
class InMemoryCollection {
  constructor(name) { this.name = name; this.documents = []; this.idCounter = 1; }

  async create(doc) {
    const newDoc = { createdAt: new Date(), updatedAt: new Date(), ...doc, _id: `mock_${this.name}_${this.idCounter++}` };
    newDoc.toObject = function () { return { ...this }; };
    this.documents.push(newDoc);
    return newDoc;
  }
  find(query = {}) { return new MockQuery(this.documents, query, this); }
  async findOne(query = {}) { return this.documents.find(d => this._match(d, query)) || null; }
  async findById(id) { return this.documents.find(d => d._id === id) || null; }
  async findOneAndUpdate(query, update, options = {}) {
    let doc = this.documents.find(d => this._match(d, query));
    if (!doc && options.upsert) {
      doc = { ...query, _id: `mock_${this.name}_${this.idCounter++}`, createdAt: new Date(), updatedAt: new Date() };
      doc.toObject = function () { return { ...this }; };
      this.documents.push(doc);
    }
    if (!doc) return null;
    if (update.$set) Object.assign(doc, update.$set);
    if (update.$addToSet) {
      for (const [k, v] of Object.entries(update.$addToSet)) {
        if (!Array.isArray(doc[k])) doc[k] = [];
        const items = v.$each ? v.$each : [v];
        for (const item of items) { if (!doc[k].includes(item)) doc[k].push(item); }
      }
    }
    for (const [k, v] of Object.entries(update).filter(([k]) => !k.startsWith("$"))) doc[k] = v;
    doc.updatedAt = new Date();
    return doc;
  }
  async findByIdAndUpdate(id, update, options = {}) {
    const doc = this.documents.find(d => d._id === id);
    if (!doc) return null;
    if (update.$set) Object.assign(doc, update.$set); else Object.assign(doc, update);
    doc.updatedAt = new Date();
    return doc;
  }
  async findByIdAndDelete(id) {
    const i = this.documents.findIndex(d => d._id === id);
    return i === -1 ? null : this.documents.splice(i, 1)[0];
  }
  async deleteMany(query = {}) {
    const before = this.documents.length;
    this.documents = this.documents.filter(d => !this._match(d, query));
    return { deletedCount: before - this.documents.length };
  }
  async countDocuments(query = {}) {
    return Object.keys(query).length === 0 ? this.documents.length : this.documents.filter(d => this._match(d, query)).length;
  }
  async insertMany(docs) { return Promise.all(docs.map(d => this.create(d))); }
  _match(doc, query) {
    for (const [k, v] of Object.entries(query)) {
      if (k === "$or") { if (!v.some(q => this._match(doc, q))) return false; }
      else if (k === "$and") { if (!v.every(q => this._match(doc, q))) return false; }
      else if (v && typeof v === "object") {
        if ("$in" in v && !v.$in.includes(doc[k])) return false;
        if ("$regex" in v && !new RegExp(v.$regex, v.$options || "").test(doc[k])) return false;
        if ("$gte" in v && doc[k] < v.$gte) return false;
        if ("$lte" in v && doc[k] > v.$lte) return false;
        if ("$gt"  in v && doc[k] <= v.$gt)  return false;
        if ("$lt"  in v && doc[k] >= v.$lt)  return false;
      } else if (doc[k] !== v) return false;
    }
    return true;
  }
}

class MockQuery {
  constructor(docs, query, col) { this._docs = docs; this._q = query; this._col = col; this._s = null; this._l = null; this._sk = 0; }
  sort(s) { this._s = s; return this; }
  limit(n) { this._l = n; return this; }
  skip(n) { this._sk = n; return this; }
  lean() { return this._run(); }
  exec() { return this._run(); }
  then(res, rej) { return this._run().then(res, rej); }
  _run() {
    let r = this._docs.filter(d => this._col._match(d, this._q));
    if (this._s) r = r.sort((a, b) => { for (const [k, o] of Object.entries(this._s)) { if (a[k] < b[k]) return o === 1 ? -1 : 1; if (a[k] > b[k]) return o === 1 ? 1 : -1; } return 0; });
    if (this._sk) r = r.slice(this._sk);
    if (this._l)  r = r.slice(0, this._l);
    return Promise.resolve(r);
  }
}

class MockSchema {
  constructor(def, opts = {}) { this.definition = def; this.options = opts; this.methods = {}; this.statics = {}; this.preHooks = []; this.postHooks = []; }
  pre(a, fn) { this.preHooks.push({ a, fn }); return this; }
  post(a, fn) { this.postHooks.push({ a, fn }); return this; }
  index() { return this; }
}
MockSchema.Types = { Mixed: "Mixed", ObjectId: "ObjectId" };

const mockCollections = new Map();
function mockModel(name, schema) {
  if (!mockCollections.has(name)) mockCollections.set(name, new InMemoryCollection(name));
  const col = mockCollections.get(name);
  if (schema) { Object.assign(col, schema.statics); col.schema = schema; }
  return col;
}

// ── Connection logic: try real MongoDB, fall back to mock ─────────────────────
let usingMock = false;

const connectMongo = async () => {
  const uri = process.env.MONGO_URI || "mongodb://localhost:27017/cti_platform";
  try {
    await mongoose.connect(uri, { serverSelectionTimeoutMS: 4000 });
    console.log("MongoDB connected (real)");
  } catch (err) {
    console.warn(`MongoDB unavailable (${err.message}) — switching to in-memory mock`);
    usingMock = true;
    // Patch mongoose so models use in-memory collections
    mongoose.Schema = MockSchema;
    mongoose.model  = mockModel;
    mongoose.disconnect = async () => {};
    mongoose.connection = new EventEmitter();
    mongoose.connection.readyState = 1;

    // ── Seed mock Alert collection so Campaign Alert page has data ─────────
    const alertCol = mockModel("Alert");
    const now = new Date();
    const seedAlerts = [
      {
        type: "campaign_match", severity: "critical",
        title: "Campaign detected: APT29_NOBELIUM",
        description: "2 known IOCs matched to campaign operated by APT29",
        campaign_id: "APT29_NOBELIUM", resolved: false,
        meta: { campaign_name: "APT29_NOBELIUM", actor_name: "APT29", matched_count: 2, matched_ips: ["203.0.113.47", "evil-cdn.net"] },
        createdAt: new Date(now - 1 * 60 * 60 * 1000),
      },
      {
        type: "campaign_match", severity: "high",
        title: "Campaign detected: TA505_Q4_2023",
        description: "2 known IOCs matched to campaign operated by TA505",
        campaign_id: "TA505_Q4_2023", resolved: false,
        meta: { campaign_name: "TA505_Q4_2023", actor_name: "TA505", matched_count: 2, matched_ips: ["198.51.100.23", "phishing-kit.ru"] },
        createdAt: new Date(now - 3 * 60 * 60 * 1000),
      },
      {
        type: "campaign_match", severity: "critical",
        title: "Campaign detected: LOCKBIT_WAVE_23",
        description: "2 known IOCs matched to campaign operated by LockBit",
        campaign_id: "LOCKBIT_WAVE_23", resolved: false,
        meta: { campaign_name: "LOCKBIT_WAVE_23", actor_name: "LockBit", matched_count: 2, matched_ips: ["10.99.88.77", "malware-drop.xyz"] },
        createdAt: new Date(now - 6 * 60 * 60 * 1000),
      },
      {
        type: "ioc_hit", severity: "high",
        title: "High-confidence IOC observed: 203.0.113.47",
        description: "IP flagged by abuse.ch with VT score 42/72. Likely C2 server.",
        ioc_value: "203.0.113.47", resolved: false,
        meta: { source: "abuse.ch", confidence: 92, tags: ["APT29", "c2"] },
        createdAt: new Date(now - 12 * 60 * 60 * 1000),
      },
      {
        type: "high_risk_device", severity: "critical",
        title: "High-risk device: DESKTOP-HR-01 (score 91)",
        description: "Device risk score exceeded critical threshold.",
        devices: ["DESKTOP-HR-01"], resolved: false,
        meta: { risk_score: 91, host: "DESKTOP-HR-01" },
        createdAt: new Date(now - 24 * 60 * 60 * 1000),
      },
    ];
    await Promise.all(seedAlerts.map(a => alertCol.create(a)));
    console.log("MongoDB mock: pre-seeded with 5 campaign alert history entries");
  }
};

module.exports = connectMongo;