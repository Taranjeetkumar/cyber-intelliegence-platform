const http = require("http");

const BACKEND_EVENT_URL = process.env.BACKEND_EVENT_URL || "http://backend:5000/api/honeypot/events";

const emitEvent = (event) => {
  const payload = JSON.stringify({
    ...event,
    capturedAt: new Date().toISOString(),
    sensorId: process.env.SENSOR_ID || event.service || "honeypod",
  });

  const url = new URL(BACKEND_EVENT_URL);
  const req = http.request(
    {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
      timeout: 2500,
    },
    (res) => {
      res.resume();
    }
  );

  req.on("error", (err) => {
    console.error("Failed to emit honeypot event:", err.message);
  });
  req.write(payload);
  req.end();
};

const normalizeIp = (value = "") => value.replace(/^::ffff:/, "");

module.exports = { emitEvent, normalizeIp };
