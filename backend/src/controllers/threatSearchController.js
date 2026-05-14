const svc = require("../services/threatSearchService");

exports.searchIOCs = async (req, res) => { try { res.json(await svc.searchIOCs(req.query)); } catch (e) { res.status(500).json({ error: e.message }); } };
exports.iocStats = async (req, res) => { try { res.json(await svc.iocStatsBySource(req.query.tag)); } catch (e) { res.status(500).json({ error: e.message }); } };
exports.iocTypeBreakdown = async (req, res) => { try { res.json(await svc.iocTypeBreakdown()); } catch (e) { res.status(500).json({ error: e.message }); } };
exports.searchReports = async (req, res) => { try { res.json(await svc.searchThreatReports(req.query)); } catch (e) { res.status(500).json({ error: e.message }); } };
exports.getTags = async (req, res) => { try { res.json(await svc.getAllTags()); } catch (e) { res.status(500).json({ error: e.message }); } };
