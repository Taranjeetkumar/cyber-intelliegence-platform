const router = require("express").Router();
const controller = require("../controllers/liveThreatIntelController");

router.post("/fetch", controller.fetchLiveData);
router.get("/status", controller.getStatus);
router.get("/campaigns", controller.searchCampaigns);
router.get("/campaigns/:id", controller.getCampaignDetails);

module.exports = router;
