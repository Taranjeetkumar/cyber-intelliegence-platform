const neo4j = require("neo4j-driver");

let driver;

const connectNeo4j = async () => {
  driver = neo4j.driver(
    process.env.NEO4J_URI,
    neo4j.auth.basic(process.env.NEO4J_USER, process.env.NEO4J_PASSWORD)
  );

  try {
    await driver.verifyConnectivity();
    console.log("Neo4j connected");
  } catch (err) {
    console.error("Neo4j connection failed:", err.message);
    process.exit(1);
  }
};

// Returns a new session — caller must close it after use
const getNeo4jSession = () => {
  if (!driver) throw new Error("Neo4j driver not initialised");
  return driver.session({ database: "neo4j" });
};

const closeNeo4j = async () => {
  if (driver) await driver.close();
};

module.exports = { connectNeo4j, getNeo4jSession, closeNeo4j };
