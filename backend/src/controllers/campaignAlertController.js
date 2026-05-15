const { runCorrelation, getAlerts, getActiveCampaigns, importLiveAbuseFeed } = require("../services/campaignAlertService");

exports.correlate = async (req, res) => { try { res.json(await runCorrelation(req.query.topN, req.query.threshold)); } catch (e) { res.status(500).json({ error: e.message }); } };
exports.getAlerts = async (req, res) => { try { res.json(await getAlerts(req.query.limit)); } catch (e) { res.status(500).json({ error: e.message }); } };
exports.activeCampaigns = async (req, res) => { try { res.json(await getActiveCampaigns()); } catch (e) { res.status(500).json({ error: e.message }); } };
exports.importLiveFeed = async (req, res) => {
  try {
    res.json(await importLiveAbuseFeed({
      limit: req.query.limit,
      confidenceMinimum: req.query.confidenceMinimum,
    }));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
