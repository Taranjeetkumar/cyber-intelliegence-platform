const { investigateIP, listKnownIPs } = require("../services/investigationService");

// GET /api/investigate/ip?value=
const investigate = async (req, res) => {
  const { value } = req.query;

  if (!value) {
    return res.status(400).json({ error: "Query param 'value' is required" });
  }

  try {
    const result = await investigateIP(value.trim());
    res.json(result);
  } catch (err) {
    console.error("Investigation error:", err);
    res.status(500).json({ error: "Investigation failed", detail: err.message });
  }
};

// GET /api/investigate/known-ips
const knownIPs = async (req, res) => {
  try {
    const ips = await listKnownIPs();
    res.json({ ips });
  } catch (err) {
    console.error("Known IPs error:", err);
    res.status(500).json({ error: "Failed to fetch known IPs" });
  }
};

module.exports = { investigate, knownIPs };
