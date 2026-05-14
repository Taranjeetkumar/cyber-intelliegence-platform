const mongoose = require("mongoose");

const honeypotEventSchema = new mongoose.Schema(
  {
    sourceIp: { type: String, required: true, index: true },
    service: {
      type: String,
      enum: ["ssh", "http", "telnet", "unknown"],
      default: "unknown",
      index: true,
    },
    protocol: { type: String, default: "tcp" },
    destinationPort: Number,
    eventType: { type: String, required: true, index: true },
    sensorId: { type: String, default: "honeypod" },
    severity: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "medium",
      index: true,
    },
    username: String,
    password: String,
    method: String,
    path: String,
    userAgent: String,
    payload: String,
    capturedAt: { type: Date, default: Date.now, index: true },
    enrichment: mongoose.Schema.Types.Mixed,
  },
  { timestamps: true }
);

honeypotEventSchema.index({ capturedAt: -1 });

module.exports = mongoose.model("HoneypotEvent", honeypotEventSchema);
