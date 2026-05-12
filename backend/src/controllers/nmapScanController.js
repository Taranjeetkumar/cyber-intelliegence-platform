const { scanIP, getScanHistory, getLatestScan } = require("../services/nmapScanService");

const runScan = async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: "ip is required in request body" });

  try {
    const result = await scanIP(ip);
    res.json(result);
  } catch (err) {
    console.error("[Nmap Controller Error]", err.message);

    // Friendly error for missing Nmap installation
    if (err.message.includes("not installed") || err.message.includes("not in PATH")) {
      return res.status(503).json({
        error: "Nmap not found",
        detail: err.message,
      });
    }

    res.status(500).json({ error: "Scan failed", detail: err.message });
  }
};

const history = async (req, res) => {
  const { ip, limit } = req.query;
  if (!ip) return res.status(400).json({ error: "ip query param required" });
  try {
    const scans = await getScanHistory(ip, limit ? parseInt(limit) : 10);
    res.json({ ip, count: scans.length, scans });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

const latest = async (req, res) => {
  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: "ip query param required" });
  try {
    const doc = await getLatestScan(ip);
    if (!doc) return res.status(404).json({ error: "No scan found for this IP" });
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

module.exports = { runScan, history, latest };
