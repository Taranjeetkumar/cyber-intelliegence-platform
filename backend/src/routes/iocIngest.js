const router = require("express").Router();
const controller = require("../controllers/iocIngestController");

router.post("/one", controller.ingestOne);
router.post("/batch", controller.ingestBatch);
router.get("/stats", controller.stats);

module.exports.iocIngestRouter = router;