const express = require("express");
const router = express.Router();
const { investigate, knownIPs } = require("../controllers/investigationController");

router.get("/ip", investigate);
router.get("/known-ips", knownIPs);

module.exports = router;
