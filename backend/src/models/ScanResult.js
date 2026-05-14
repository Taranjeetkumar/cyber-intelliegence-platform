const mongoose = require("mongoose");

const portSchema = new mongoose.Schema({
  number: { type: Number, required: true },
  protocol: { type: String, default: "tcp" },
  state: { type: String, enum: ["open", "closed", "filtered", "open|filtered", "open_filtered"], default: "closed" },
  service: { type: String, default: "" },
  version: { type: String, default: "" },
  scripts: { type: mongoose.Schema.Types.Mixed, default: {} },
}, { _id: false });

const tracerouteHopSchema = new mongoose.Schema({
  hop: { type: Number },
  rtt_ms: { type: Number },
  host: { type: String },
}, { _id: false });

const scanResultSchema = new mongoose.Schema(
  {
    ip: { type: String, required: true },
    hostname: { type: String, default: "" },
    status: { type: String, enum: ["up", "down", "unknown"], default: "unknown" },
    ports: [portSchema],
    open_count: { type: Number, default: 0 },
    risk_score: { type: Number, default: 0 },
    os: { type: String, default: null },
    os_accuracy: { type: Number, default: null },
    latency: { type: Number, default: null },
    mac_address: { type: String, default: null },
    mac_vendor: { type: String, default: null },
    traceroute: [tracerouteHopSchema],
    scripts: { type: mongoose.Schema.Types.Mixed, default: {} },
    raw_output: { type: String, default: "" },
    scan_source: { type: String, default: "local-nmap" },
    scan_ts: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

scanResultSchema.index({ ip: 1, scan_ts: -1 });

module.exports = mongoose.model("ScanResult", scanResultSchema);