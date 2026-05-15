const mongoose = require("mongoose");

const campaignSchema = new mongoose.Schema(
  {
    campaign_id: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    name: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      default: "",
    },
    author: {
      type: String,
      default: "unknown",
    },
    threat_actor: {
      type: String,
      default: null,
    },
    tags: {
      type: [String],
      default: [],
    },
    targeted_countries: {
      type: [String],
      default: [],
    },
    industries: {
      type: [String],
      default: [],
    },
    malware_families: {
      type: [String],
      default: [],
    },
    iocs: {
      ips: { type: [String], default: [] },
      domains: { type: [String], default: [] },
      urls: { type: [String], default: [] },
      hashes: { type: [String], default: [] },
      emails: { type: [String], default: [] },
    },
    references: {
      type: [String],
      default: [],
    },
    severity: {
      type: String,
      enum: ["critical", "high", "medium", "low", "info"],
      default: "medium",
    },
    confidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 50,
    },
    source: {
      type: String,
      required: true,
      enum: ["otx", "misp", "abuse_ch", "manual", "threatfox", "urlhaus"],
      default: "otx",
    },
    source_id: {
      type: String,
      default: null,
    },
    source_url: {
      type: String,
      default: null,
    },
    first_seen: {
      type: Date,
      default: Date.now,
    },
    last_modified: {
      type: Date,
      default: Date.now,
    },
    is_active: {
      type: Boolean,
      default: true,
    },
    adversary: {
      type: String,
      default: null,
    },
    tlp: {
      type: String,
      enum: ["white", "green", "amber", "red"],
      default: "white",
    },
  },
  {
    timestamps: true,
  }
);

// Indexes for efficient querying
campaignSchema.index({ tags: 1 });
campaignSchema.index({ threat_actor: 1 });
campaignSchema.index({ source: 1 });
campaignSchema.index({ "iocs.ips": 1 });
campaignSchema.index({ "iocs.domains": 1 });
campaignSchema.index({ createdAt: -1 });

module.exports = mongoose.model("Campaign", campaignSchema);
