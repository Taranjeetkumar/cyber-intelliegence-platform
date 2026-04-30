require("dotenv").config();
const express = require("express");
const cors = require("cors");

const connectMongo = require("./config/mongo");
const { connectRedis } = require("./config/redis");
const { connectNeo4j } = require("./config/neo4j");
const errorHandler = require("./middleware/errorHandler");
const investigationRoutes = require("./routes/investigation");

const app = express();

// Middleware
app.use(cors({ origin: process.env.FRONTEND_URL }));
app.use(express.json());

// Routes 
app.get("/api/health", (req, res) =>
  res.json({ status: "ok", time: new Date().toISOString() })
);

app.use("/api/investigate", investigationRoutes);

// Error handler 
app.use(errorHandler);

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
