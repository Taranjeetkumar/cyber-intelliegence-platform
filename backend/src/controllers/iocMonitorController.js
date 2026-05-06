const { getLiveLeaderboard, getDeviceRiskScores, getActiveCampaigns, recordIocHit } = require("../services/iocMonitorService");

exports.leaderboard = async (req, res) => { try { res.json(await getLiveLeaderboard(req.query.limit)); } catch (e) { res.status(500).json({ error: e.message }); } };
exports.deviceScores = async (req, res) => { try { res.json(await getDeviceRiskScores()); } catch (e) { res.status(500).json({ error: e.message }); } };
exports.activeCampaigns = async (req, res) => { try { res.json(await getActiveCampaigns()); } catch (e) { res.status(500).json({ error: e.message }); } };
exports.recordHit = async (req, res) => { try { res.json(await recordIocHit(req.body.value)); } catch (e) { res.status(500).json({ error: e.message }); } };
