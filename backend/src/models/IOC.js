const mongoose = require("mongoose");

const iocSchema = new mongoose.Schema(
  {
    value: { type: String, required: true },
    type: { type: String, enum: ["ip", "domain", "hash", "url"], required: true },
    tags: [String],
    confidence: { type: Number, min: 0, max: 100, default: 50 },
    first_seen: { type: Date, default: Date.now },
    last_seen: { type: Date, default: Date.now },
    source: { type: String, default: "manual" },
    enrichment: {
      whois_country: String,
      asn: String,
      virustotal_score: String,
      isp: String,
    },
    analyst_notes: String,
  },
  { timestamps: true }
);

iocSchema.index({ value: 1, type: 1 }, { unique: true });
iocSchema.index({ tags: 1 });
iocSchema.index({ confidence: -1 });

module.exports = mongoose.model("IOC", iocSchema);
