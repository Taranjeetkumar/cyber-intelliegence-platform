const router = require("express").Router();
const { runScan, history, latest } = require("../controllers/nmapScanController");

router.post("/run", runScan);
router.get("/history", history);
router.get("/result", latest);

module.exports = router;
