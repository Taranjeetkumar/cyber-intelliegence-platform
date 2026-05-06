const { ingestSingleIOC, ingestBatch, getIngestionStats } = require("../services/iocIngestService");

exports.ingestOne = async (req, res) => { try { res.json(await ingestSingleIOC(req.body)); } catch (e) { res.status(400).json({ error: e.message }); } };
exports.ingestBatch = async (req, res) => { try { res.json(await ingestBatch(req.body.iocs)); } catch (e) { res.status(400).json({ error: e.message }); } };
exports.stats = async (req, res) => { try { res.json(await getIngestionStats()); } catch (e) { res.status(500).json({ error: e.message }); } };
