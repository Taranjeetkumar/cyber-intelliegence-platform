const express = require("express");
const { createEvent, recentEvents } = require("../controllers/honeypotController");

const router = express.Router();

router.post("/events", createEvent);
router.get("/events", recentEvents);

module.exports = router;
