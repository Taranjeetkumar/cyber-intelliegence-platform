const router = require("express").Router();
const controller = require("../controllers/threatSearchController");

router.get("/iocs", controller.searchIOCs);
router.get("/stats", controller.iocStats);
router.get("/breakdown", controller.iocTypeBreakdown);
router.get("/reports", controller.searchReports);
router.get("/tags", controller.getTags);

module.exports = router;
