const { exec } = require("child_process");
const ScanResult = require("../models/ScanResult");
const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");

const NMAP_PATH = process.env.NMAP_PATH || "nmap";

const runNmap = (ip) =>
  new Promise((resolve, reject) => {
    // Sanitise input — only allow safe chars (IP, hostname, CIDR)
    if (!/^[a-zA-Z0-9.\-_/]+$/.test(ip)) {
      return reject(new Error("Invalid IP or hostname characters detected"));
    }

    console.log('logsvjhvf :  ', NMAP_PATH)
    const cmd = `"${NMAP_PATH}" -sV -T4 --open ${ip}`;
    console.log(`Nmap Running check: ${cmd}`);

    exec(cmd, { timeout: 120000 }, (err, stdout, stderr) => {
      if (err && !stdout) {
        console.log('nbgtfdewsdfrdeg :  ', err)

        // nmap not found
        if (err.message.includes("not found") || err.message.includes("ENOENT") || err.message.includes("is not recognized")) {
          return reject(new Error(
            "Nmap is not installed or not in PATH. "
          ));
        }
        return reject(new Error(err.message));
      }
      resolve(stdout || "");
    });
  });


const parseNmapOutput = (raw, originalInput) => {
  const lines = raw.split("\n").map(l => l.trim()).filter(Boolean);

  const result = {
    ip: originalInput,
    hostname: originalInput,
    status: "unknown",
    ports: [],
    raw_output: raw,
    scan_ts: new Date(),
  };

  for (const line of lines) {
    if (line.startsWith("Nmap scan report for")) {
      const m = line.match(/for (.+?)(?:\s+\((.+?)\))?$/);
      if (m) {
        result.hostname = m[1].trim();
        if (m[2]) result.ip = m[2].trim(); // extract real IP
      }
    }

    if (line.startsWith("Host is up")) result.status = "up";
    if (line.startsWith("Host is down")) result.status = "down";

    const m = line.match(/^(\d+)\/(tcp|udp)\s+(open(?:\|filtered)?|closed|filtered)\s+(\S+)(?:\s+(.+))?$/);
    if (m) {
      result.ports.push({
        number: parseInt(m[1]),
        protocol: m[2],
        state: m[3].replace("|", "_"), // "open|filtered" → "open_filtered"
        service: m[4],
        version: m[5] ? m[5].trim() : "",
      });
    }
  }

  result.open_count = result.ports.filter(p => p.state === "open" || p.state === "open_filtered").length;
  result.risk_score = Math.min(result.open_count * 10, 100);

  return result;
};

const saveToMongo = async (parsed) => {
  return ScanResult.create({
    ip: parsed.ip,
    hostname: parsed.hostname,
    status: parsed.status,
    ports: parsed.ports,
    open_count: parsed.open_count,
    risk_score: parsed.risk_score,
    raw_output: parsed.raw_output,
    scan_source: "local-nmap",
    scan_ts: parsed.scan_ts,
  });
};


const saveToNeo4j = async (parsed) => {
  const openPorts = parsed.ports.filter(p => p.state === "open" || p.state === "open_filtered");
  if (!openPorts.length) return 0;

  const session = getNeo4jSession();
  try {
    for (const port of openPorts) {
      await session.run(
        `
        MERGE (d:Device {ip: $ip})
        ON CREATE SET d.hostname = $hostname, d.first_seen = $ts, d.os = "unknown"
        ON MATCH  SET d.last_seen = $ts

        WITH d
        MERGE (p:Port {number: $portNum, protocol: $protocol})
        ON CREATE SET p.state = $state

        WITH d, p
        MERGE (s:Service {name: $service, version: $version})

        MERGE (d)-[:HAS_PORT]->(p)
        MERGE (p)-[:RUNS]->(s)
        `,
        {
          ip: parsed.ip,
          hostname: parsed.hostname,
          ts: new Date().toISOString(),
          portNum: port.number,
          protocol: port.protocol,
          state: port.state,
          service: port.service || "unknown",
          version: port.version || "",
        }
      );
    }
  } finally {
    await session.close();
  }

  return openPorts.length;
};


const saveToRedis = async (parsed) => {
  const redis = getRedis();
  const hostKey = `risk:host:${parsed.ip}`;

  await redis.set(hostKey, String(parsed.risk_score), { EX: 3600 });

  if (parsed.open_count > 0) {
    await redis.zAdd("hot:iocs", [{ score: parsed.risk_score, value: parsed.ip }]);
  }

  return { key: hostKey, score: parsed.risk_score, ttl: 3600 };
};



const scanIP = async (ip) => {
  if (!ip || typeof ip !== "string") throw new Error("IP or hostname is required");
  const target = ip.trim();

  const raw = await runNmap(target);
  const parsed = parseNmapOutput(raw, target);

  console.log(`[Nmap] Result: ${parsed.ports.length} ports found, ${parsed.open_count} open, risk=${parsed.risk_score}`);

  // 3: MongoDB
  const mongoDoc = await saveToMongo(parsed);

  // 4: Neo4j (only if host is up and has open ports)
  let neo4jNodes = 0;
  if (parsed.status === "up" && parsed.open_count > 0) {
    neo4jNodes = await saveToNeo4j(parsed);
  }

  // 5: Redis
  const redisResult = await saveToRedis(parsed);

  return {
    scan: {
      ip: parsed.ip,
      hostname: parsed.hostname,
      status: parsed.status,
      ports: parsed.ports,
      open_count: parsed.open_count,
      risk_score: parsed.risk_score,
      scan_ts: parsed.scan_ts,
    },
    db_writes: {
      mongodb: { id: mongoDoc._id, collection: "scan_results" },
      neo4j: { nodes_merged: neo4jNodes, description: "Port+Service nodes merged into graph" },
      redis: redisResult,
    },
  };
};


const getScanHistory = async (ip, limit = 10) => {
  if (!ip) throw new Error("IP is required");
  return ScanResult.find({ ip: ip.trim() }).sort({ scan_ts: -1 }).limit(limit).lean();
};


const getLatestScan = async (ip) => {
  if (!ip) throw new Error("IP is required");
  return ScanResult.findOne({ ip: ip.trim() }).sort({ scan_ts: -1 }).lean();
};

module.exports = { scanIP, getScanHistory, getLatestScan };
