const router = require("express").Router();
const controller = require("../controllers/campaignAlertController");
 
router.post("/correlate", controller.correlate);
router.get("/alerts", controller.getAlerts);
router.get("/active", controller.activeCampaigns);
router.delete("/active", controller.clearActive);
router.get("/stats", controller.getStats);
 
module.exports.campaignAlertRouter = router;
 
 