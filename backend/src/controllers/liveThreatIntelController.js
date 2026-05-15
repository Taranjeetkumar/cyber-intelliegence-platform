const {
  fetchAndStoreLiveThreatIntel,
  getFetchStatus,
  searchCampaigns,
  getCampaignDetails,
} = require("../services/liveThreatIntelService");

/**
 * Trigger live data fetch from OTX
 */
exports.fetchLiveData = async (req, res) => {
  try {
    const { source = "recent", query, limit = 20, page = 1 } = req.query;

    console.log(`[LiveThreatIntel] Fetch triggered: source=${source}, limit=${limit}`);

    const stats = await fetchAndStoreLiveThreatIntel({
      source,
      query,
      limit: parseInt(limit, 10),
      page: parseInt(page, 10),
    });

    res.json({
      success: true,
      message: "Live threat intelligence data fetched and stored",
      stats,
    });
  } catch (error) {
    console.error("[LiveThreatIntel] Fetch error:", error.message);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
};

/**
 * Get fetch status and statistics
 */
exports.getStatus = async (req, res) => {
  try {
    const status = await getFetchStatus();
    res.json(status);
  } catch (error) {
    console.error("[LiveThreatIntel] Status error:", error.message);
    res.status(500).json({ error: error.message });
  }
};

/**
 * Search campaigns
 */
exports.searchCampaigns = async (req, res) => {
  try {
    const campaigns = await searchCampaigns(req.query);
    res.json(campaigns);
  } catch (error) {
    console.error("[LiveThreatIntel] Search error:", error.message);
    res.status(500).json({ error: error.message });
  }
};

/**
 * Get campaign details
 */
exports.getCampaignDetails = async (req, res) => {
  try {
    const { id } = req.params;
    const campaign = await getCampaignDetails(id);

    if (!campaign) {
      return res.status(404).json({ error: "Campaign not found" });
    }

    res.json(campaign);
  } catch (error) {
    console.error("[LiveThreatIntel] Details error:", error.message);
    res.status(500).json({ error: error.message });
  }
};
