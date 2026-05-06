/**
 * UC3 — Search Threat Reports
 * Primary DB: MongoDB
 * Uses: compound queries, $in, $gte, aggregation pipeline, $group/$sort
 */
const IOC = require("../models/IOC");
const ThreatReport = require("../models/ThreatReport");

// Search IOCs with compound filter
// Shows off: $in on array field, date range $gte, compound index, projection
const searchIOCs = async ({ tag, minConfidence = 0, days, type, source, limit = 50 }) => {
    const filter = {};

    if (tag) filter.tags = { $in: [tag] };
    if (type) filter.type = type;
    if (source) filter.source = source;
    if (minConfidence) filter.confidence = { $gte: Number(minConfidence) };
    if (days) {
        filter.last_seen = {
            $gte: new Date(Date.now() - Number(days) * 24 * 60 * 60 * 1000),
        };
    }

    const results = await IOC.find(filter)
        .sort({ confidence: -1 })
        .limit(Number(limit))
        .lean();

    return results;
};

// Aggregation: group IOCs by source feed and count
// Shows off: $match → $group → $sort pipeline
const iocStatsBySource = async (tag) => {
    const match = tag ? { tags: tag } : {};

    const pipeline = [
        { $match: match },
        { $group: { _id: "$source", count: { $sum: 1 }, avg_confidence: { $avg: "$confidence" } } },
        { $sort: { count: -1 } },
    ];

    return IOC.aggregate(pipeline);
};

// Aggregation: IOC type breakdown
const iocTypeBreakdown = async () => {
    return IOC.aggregate([
        { $group: { _id: "$type", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
    ]);
};

// Search threat reports
const searchThreatReports = async ({ tag, severity, minConfidence = 0, days, limit = 20 }) => {
    const filter = {};

    if (tag) filter.tags = { $in: [tag] };
    if (severity) filter.severity = severity;
    if (minConfidence) filter.confidence = { $gte: Number(minConfidence) };
    if (days) {
        filter.date_published = {
            $gte: new Date(Date.now() - Number(days) * 24 * 60 * 60 * 1000),
        };
    }

    return ThreatReport.find(filter)
        .sort({ date_published: -1, confidence: -1 })
        .limit(Number(limit))
        .lean();
};

// Get all unique tags for filter dropdowns
const getAllTags = async () => {
    const iocTags = await IOC.distinct("tags");
    const reportTags = await ThreatReport.distinct("tags");
    return [...new Set([...iocTags, ...reportTags])].sort();
};

module.exports = { searchIOCs, iocStatsBySource, iocTypeBreakdown, searchThreatReports, getAllTags };
