const mongoose = require("mongoose");

const portSchema = new mongoose.Schema({
  number:   { type: Number, required: true },
  protocol: { type: String, default: "tcp" },
  state:    { type: String, enum: ["open", "closed", "filtered", "open|filtered"], default: "closed" },
  service:  { type: String, default: "" },
  version:  { type: String, default: "" },
}, { _id: false });

const scanResultSchema = new mongoose.Schema(
  {
    ip:          { type: String, required: true },
    hostname:    { type: String, default: "" },
    status:      { type: String, enum: ["up", "down", "unknown"], default: "unknown" },
    ports:       [portSchema],
    open_count:  { type: Number, default: 0 },
    risk_score:  { type: Number, default: 0 },
    raw_output:  { type: String, default: "" },
    scan_source: { type: String, default: "local-nmap" },
    scan_ts:     { type: Date, default: Date.now },
  },
  { timestamps: true }
);

scanResultSchema.index({ ip: 1, scan_ts: -1 });

module.exports = mongoose.model("ScanResult", scanResultSchema);
