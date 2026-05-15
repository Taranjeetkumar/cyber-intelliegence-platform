const {
  runCorrelation,
  getAlerts,
  getActiveCampaigns,
  clearActiveCampaigns,
  getCorrelationStats,
} = require("../services/campaignAlertService");
 
exports.correlate = async (req, res) => {
  try {
    const result = await runCorrelation(req.query.topN, req.query.threshold);
    res.json(result);
  } catch (e) {
    console.error("[CampaignAlert] Correlate error:", e.message);
    res.status(500).json({ error: e.message });
  }
};
 
exports.getAlerts = async (req, res) => {
  try {
    const alerts = await getAlerts(req.query.limit);
    res.json(alerts);
  } catch (e) {
    console.error("[CampaignAlert] GetAlerts error:", e.message);
    res.status(500).json({ error: e.message });
  }
};
 
exports.activeCampaigns = async (req, res) => {
  try {
    const campaigns = await getActiveCampaigns();
    res.json(campaigns);
  } catch (e) {
    console.error("[CampaignAlert] ActiveCampaigns error:", e.message);
    res.status(500).json({ error: e.message });
  }
};
 
exports.clearActive = async (req, res) => {
  try {
    const result = await clearActiveCampaigns();
    res.json({ success: true, ...result });
  } catch (e) {
    console.error("[CampaignAlert] ClearActive error:", e.message);
    res.status(500).json({ error: e.message });
  }
};
 
exports.getStats = async (req, res) => {
  try {
    const stats = await getCorrelationStats();
    res.json(stats);
  } catch (e) {
    console.error("[CampaignAlert] GetStats error:", e.message);
    res.status(500).json({ error: e.message });
  }
};
 
 