const mongoose = require("mongoose");

const alertSchema = new mongoose.Schema(
    {
        type: { type: String, enum: ["ioc_hit", "campaign_match", "attack_chain", "high_risk_device"], required: true },
        severity: { type: String, enum: ["low", "medium", "high", "critical"], default: "medium" },
        title: { type: String, required: true },
        description: String,
        ioc_value: String,
        campaign_id: String,
        devices: [String],
        resolved: { type: Boolean, default: false },
        meta: mongoose.Schema.Types.Mixed,
    },
    { timestamps: true }
);

alertSchema.index({ severity: 1, resolved: 1 });
alertSchema.index({ createdAt: -1 });

module.exports = mongoose.model("Alert", alertSchema);
