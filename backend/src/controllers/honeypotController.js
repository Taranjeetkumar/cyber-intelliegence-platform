const {
  listRecentHoneypotEvents,
  recordHoneypotEvent,
} = require("../services/honeypotService");

const createEvent = async (req, res, next) => {
  try {
    const event = await recordHoneypotEvent(req.body);
    res.status(201).json({ event });
  } catch (err) {
    next(err);
  }
};

const recentEvents = async (req, res, next) => {
  try {
    const events = await listRecentHoneypotEvents(req.query.limit);
    res.json({ events });
  } catch (err) {
    next(err);
  }
};

module.exports = { createEvent, recentEvents };
