const { getAtRiskDevices } = require("../services/deviceRiskService");

exports.atRisk = async (req, res) => {
  try {
    const minCvss = req.query.minCvss ? parseFloat(req.query.minCvss) : 7.0;
    res.json(await getAtRiskDevices(minCvss));
  } catch(e) { res.status(500).json({error: e.message}); }
};
