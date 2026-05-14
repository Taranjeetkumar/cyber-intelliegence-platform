require("dotenv").config();
const express = require("express");
const cors = require("cors");
const http = require("http");

const connectMongo = require("./config/mongo");
const { connectRedis, getRedis } = require("./config/redis");
const { connectNeo4j } = require("./config/neo4j");
const errorHandler = require("./middleware/errorHandler");

const investigationRoutes = require("./routes/investigation");
const honeypotRoutes = require("./routes/honeypot");
const iocMonitorRoutes = require("./routes/iocMonitor");
const threatSearchRoutes = require("./routes/threatSearch");
const { deviceRiskRouter, } = require("./routes/deviceRisk");
const { iocIngestRouter } = require("./routes/iocIngest");
const { campaignAlertRouter } = require("./routes/campaignAlert");
const nmapScanRoutes = require("./routes/nmapScan");

const app = express();
const server = http.createServer(app);

// Middleware
app.use(cors({ origin: process.env.FRONTEND_URL || "http://localhost:3000" }));
app.use(express.json());

// Routes 
app.get("/api/health", (req, res) =>
  res.json({ status: "ok", time: new Date().toISOString() })
);

app.use("/api/investigate", investigationRoutes);
app.use("/api/honeypot", honeypotRoutes);
app.use("/api/monitor", iocMonitorRoutes);
app.use("/api/search", threatSearchRoutes);
app.use("/api/devices", deviceRiskRouter);
app.use("/api/ingest", iocIngestRouter);
app.use("/api/campaigns", campaignAlertRouter);
app.use("/api/scan", nmapScanRoutes);

// Error handler 
app.use(errorHandler);

app.get("/api/alerts/stream", async (req, res) => {
  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.flushHeaders();

  const subscriber = getRedis().duplicate();
  await subscriber.connect();
  await subscriber.subscribe("alert:stream", (message) => {
    res.write(`data: ${message}\n\n`);
  });

  const ping = setInterval(() => res.write(": ping\n\n"), 20000);
  req.on("close", () => {
    clearInterval(ping);
    subscriber.unsubscribe().then(() => subscriber.disconnect());
  });
});

// Startup
const start = async () => {
  await connectMongo();
  await connectRedis();
  await connectNeo4j();

  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () =>
    console.log(`API running at http://localhost:${PORT}`)
  );
};

start();
