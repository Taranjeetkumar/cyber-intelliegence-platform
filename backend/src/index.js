require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const http    = require("http");

const connectMongo  = require("./config/mongo");
const { connectRedis, getRedis, createSubscriber } = require("./config/redis");
const { connectNeo4j } = require("./config/neo4j");
const errorHandler  = require("./middleware/errorHandler");

const investigationRoutes  = require("./routes/investigation");
const honeypotRoutes       = require("./routes/honeypot");
const iocMonitorRoutes     = require("./routes/iocMonitor");
const threatSearchRoutes   = require("./routes/threatSearch");
const { deviceRiskRouter } = require("./routes/deviceRisk");
const { iocIngestRouter }  = require("./routes/iocIngest");
const { campaignAlertRouter } = require("./routes/campaignAlert");
const nmapScanRoutes       = require("./routes/nmapScan");

const app    = express();
const server = http.createServer(app);

app.use(cors({ origin: process.env.FRONTEND_URL || "http://localhost:3000" }));
app.use(express.json());

app.get("/api/health", (req, res) =>
  res.json({ status: "ok", time: new Date().toISOString() })
);

app.use("/api/investigate",  investigationRoutes);
app.use("/api/honeypot",     honeypotRoutes);
app.use("/api/monitor",      iocMonitorRoutes);
app.use("/api/search",       threatSearchRoutes);
app.use("/api/devices",      deviceRiskRouter);
app.use("/api/ingest",       iocIngestRouter);
app.use("/api/campaigns",    campaignAlertRouter);
app.use("/api/scan",         nmapScanRoutes);

// ── SSE — live alert stream ───────────────────────────────────────────────────
app.get("/api/alerts/stream", async (req, res) => {
  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  let subscriber   = null;
  let pingInterval = null;

  try {
    // createSubscriber() gives a fresh unconnected duplicate — safe to .connect()
    subscriber = createSubscriber();
    await subscriber.connect();

    await subscriber.subscribe("alert:stream", (message) => {
      try { res.write(`data: ${message}\n\n`); } catch (_) {}
    });

    // Initial handshake so the browser flips to "connected"
    res.write(`data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString() })}\n\n`);

    // Keep-alive ping every 25 s
    pingInterval = setInterval(() => {
      try { res.write(": ping\n\n"); } catch (e) { clearInterval(pingInterval); }
    }, 25000);

    req.on("close", async () => {
      if (pingInterval) clearInterval(pingInterval);
      try { await subscriber.unsubscribe("alert:stream"); await subscriber.quit(); } catch (_) {}
    });

  } catch (err) {
    console.error("SSE setup error:", err.message);
    if (pingInterval) clearInterval(pingInterval);
    try { await subscriber?.quit(); } catch (_) {}
    res.write(`data: ${JSON.stringify({ type: "error", message: err.message })}\n\n`);
    res.end();
  }
});

app.use(errorHandler);

// ── Startup — never crash on DB failure ──────────────────────────────────────
const start = async () => {
  // All three connect functions now fall back to in-memory mocks on failure
  // instead of calling process.exit(), so the server always starts.
  await connectMongo();
  await connectRedis();
  await connectNeo4j();

  const PORT = process.env.PORT || 5000;
  server.listen(PORT, "0.0.0.0", () =>
    console.log(`API running at http://localhost:${PORT}`)
  );
};

start().catch(err => {
  console.error("Fatal startup error:", err.message);
  process.exit(1);
});