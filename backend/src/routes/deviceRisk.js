const router = require("express").Router();
const controller = require("../controllers/deviceRiskController");

router.get("/at-risk", controller.atRisk);

module.exports.deviceRiskRouter = router;