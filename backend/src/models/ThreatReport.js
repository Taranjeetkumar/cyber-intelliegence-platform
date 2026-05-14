const mongoose = require("mongoose");

const threatReportSchema = new mongoose.Schema(
    {
        title: { type: String, required: true },
        source: String,
        narrative: String,
        tags: [String],
        iocs: [String],
        confidence: { type: Number, min: 0, max: 100, default: 50 },
        severity: { type: String, enum: ["low", "medium", "high", "critical"], default: "medium" },
        references: [String],
        analyst_notes: String,
        date_published: { type: Date, default: Date.now },
    },
    { timestamps: true }
);

threatReportSchema.index({ tags: 1 });
threatReportSchema.index({ confidence: -1 });
threatReportSchema.index({ date_published: -1 });

module.exports = mongoose.model("ThreatReport", threatReportSchema);
