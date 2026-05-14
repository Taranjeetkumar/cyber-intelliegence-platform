const router = require("express").Router();
const controller = require("../controllers/iocMonitorController");

router.get("/leaderboard", controller.leaderboard);
router.get("/device-scores", controller.deviceScores);
router.get("/active-campaigns", controller.activeCampaigns);
router.post("/hit", controller.recordHit);

module.exports = router;
