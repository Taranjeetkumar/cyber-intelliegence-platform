const { exec } = require("child_process");
const ScanResult = require("../models/ScanResult");
const { getNeo4jSession } = require("../config/neo4j");
const { getRedis } = require("../config/redis");

const NMAP_PATH = process.env.NMAP_PATH || "nmap";

const detectIPType = (input) => {
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const m = input.match(ipv4);
  if (!m) return "hostname";
  const [, a, b] = m.map(Number);
  if (a === 127) return "loopback";
  if (a === 10) return "private";
  if (a === 172 && b >= 16 && b <= 31) return "private";
  if (a === 192 && b === 168) return "private";
  if (a === 169 && b === 254) return "private";
  return "public";
};

const buildNmapCommand = (target, ipType) => {
  const bin = `"${NMAP_PATH}"`;
  const common = `-sV -T4 --open -Pn`;

  switch (ipType) {
    case "loopback":
      return `${bin} ${common} -n --script=banner,http-title,ssh-hostkey,ssl-cert --script-timeout 10s ${target}`;
    case "private":
      return `${bin} ${common} -n --host-timeout 90s --script=banner,http-title,ssh-hostkey,ssl-cert --script-timeout 10s ${target}`;
    case "public":
      return `${bin} ${common} --traceroute --script=banner,http-title,http-headers,ssl-cert,whois-ip --script-timeout 15s ${target}`;
    case "hostname":
    default:
      return `${bin} ${common} --traceroute --script=banner,http-title,ssl-cert,whois-ip --script-timeout 15s ${target}`;
  }
};

const runNmap = (target) =>
  new Promise((resolve, reject) => {
    if (!/^[a-zA-Z0-9.\-_/]+$/.test(target)) {
      return reject(new Error("Invalid characters in IP or hostname"));
    }
    const ipType = detectIPType(target);
    const cmd = buildNmapCommand(target, ipType);
    console.log(`[Nmap] Type: ${ipType} | Command: ${cmd}`);
    exec(cmd, { timeout: 180000 }, (err, stdout, stderr) => {
      if (err && !stdout) {
        if (err.message.includes("not found") || err.message.includes("ENOENT") || err.message.includes("is not recognized")) {
          return reject(new Error("Nmap is not installed or not in PATH. "));
        }
        return reject(new Error(err.message));
      }

      resolve({ raw: stdout || "", ipType, stderr: stderr || "" });
    });
  });

const parseNmapOutput = (raw, originalInput, ipType) => {
  const lines = raw.split("\n").map(l => l.trim()).filter(Boolean);

  const result = {
    ip: originalInput,
    hostname: originalInput,
    ip_type: ipType,
    status: "unknown",
    ports: [],
    os: null,
    os_accuracy: null,
    latency: null,
    mac_address: null,
    mac_vendor: null,
    traceroute: [],
    scripts: {},
    raw_output: raw,
    scan_ts: new Date(),
  };

  let inScriptBlock = false;
  let currentPort = null;
  let currentScriptName = null;
  let scriptLines = [];
  let inTraceroute = false;

  const flushScript = () => {
    if (currentScriptName && scriptLines.length && currentPort) {
      const key = `${currentPort}/${currentScriptName}`;
      const val = scriptLines.join("\n").trim();
      result.scripts[key] = val;
      const lastPort = result.ports[result.ports.length - 1];
      if (lastPort) lastPort.scripts[currentScriptName] = val;
    }
    currentScriptName = null;
    scriptLines = [];
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith("Nmap scan report for")) {
      const m = line.match(/for (.+?)(?:\s+\((.+?)\))?$/);
      if (m) {
        result.hostname = m[1].trim();
        if (m[2]) result.ip = m[2].trim();
        else if (/^\d+\.\d+\.\d+\.\d+$/.test(m[1].trim())) result.ip = m[1].trim();
      }
    }

    if (line.startsWith("Host is up")) {
      result.status = "up";
      const latM = line.match(/\(([0-9.]+)s latency\)/);
      if (latM) result.latency = parseFloat(latM[1]);
    }
    if (line.startsWith("Host is down")) result.status = "down";
    if (line.includes("hosts up")) result.status = result.status === "unknown" ? "up" : result.status;

    const macM = line.match(/MAC Address: ([0-9A-F:]{17})(?:\s+\((.+?)\))?/i);
    if (macM) { result.mac_address = macM[1]; result.mac_vendor = macM[2] || null; }

    const portM = line.match(/^(\d+)\/(tcp|udp)\s+(open(?:\|filtered)?|closed|filtered)\s+(\S+)(?:\s+(.+))?$/);
    if (portM) {
      flushScript();
      currentPort = portM[1];
      result.ports.push({
        number: parseInt(portM[1]),
        protocol: portM[2],
        state: portM[3].replace("|", "_"),
        service: portM[4],
        version: portM[5] ? portM[5].trim() : "",
        scripts: {},
      });
      inScriptBlock = false;
      inTraceroute = false;
      continue;
    }

    const scriptM = line.match(/^\|[_\s]\s*([\w-]+):\s*(.+)?$/);
    if (scriptM && currentPort) {
      flushScript();
      currentScriptName = scriptM[1];
      scriptLines = scriptM[2] ? [scriptM[2]] : [];
      inScriptBlock = true;
      continue;
    }
    if (inScriptBlock && line.startsWith("|")) {
      scriptLines.push(line.replace(/^\|[_ ]?/, ""));
      continue;
    }
    if (inScriptBlock && !line.startsWith("|")) {
      flushScript();
      inScriptBlock = false;
    }

    const osM = line.match(/^OS details:\s+(.+)$/);
    if (osM) result.os = osM[1].trim();

    if (!result.os) {
      const runM = line.match(/^Running(?:\s+\(JUST GUESSING\))?:\s+(.+)$/);
      if (runM) result.os = runM[1].split(",")[0].trim();
    }

    if (!result.os) {
      const aggrM = line.match(/^Aggressive OS guesses:\s+(.+)$/);
      if (aggrM) {
        const first = aggrM[1].split(",")[0];
        const accM = first.match(/(.+?)\s+\((\d+)%\)/);
        if (accM) { result.os = accM[1].trim(); result.os_accuracy = parseInt(accM[2]); }
        else result.os = first.trim();
      }
    }

    if (line.startsWith("TRACEROUTE")) { inTraceroute = true; continue; }
    if (inTraceroute) {
      const hopM = line.match(/^(\d+)\s+([0-9.]+)\s+ms\s+(\S+)/);
      if (hopM) {
        result.traceroute.push({ hop: parseInt(hopM[1]), rtt_ms: parseFloat(hopM[2]), host: hopM[3] });
      } else if (!line.match(/^(\d+|\s)/)) {
        inTraceroute = false;
      }
    }
  }
  flushScript();

  result.open_count = result.ports.filter(p => p.state === "open" || p.state === "open_filtered").length;

  const SENSITIVE_SERVICES = ["telnet", "ftp", "smtp", "rdp", "vnc", "rsh", "rlogin", "tftp", "snmp"];
  const HIGH_RISK_PORTS = [21, 23, 445, 3389, 5900, 161, 1433, 3306, 5432, 27017];
  let risk = 0;
  for (const p of result.ports) {
    if (p.state !== "open" && p.state !== "open_filtered") continue;
    let pts = (ipType === "private" || ipType === "loopback") ? 15 : 10;
    if (SENSITIVE_SERVICES.includes(p.service?.toLowerCase())) pts += 20;
    if (HIGH_RISK_PORTS.includes(p.number)) pts += 15;
    risk += pts;
  }
  result.risk_score = Math.min(risk, 100);

  return result;
};

const saveToMongo = async (parsed) => {
  return ScanResult.create({
    ip: parsed.ip,
    hostname: parsed.hostname,
    status: parsed.status,
    ports: parsed.ports.map(p => ({
      number: p.number, protocol: p.protocol, state: p.state,
      service: p.service, version: p.version, scripts: p.scripts,
    })),
    open_count: parsed.open_count,
    risk_score: parsed.risk_score,
    os: parsed.os,
    os_accuracy: parsed.os_accuracy,
    latency: parsed.latency,
    mac_address: parsed.mac_address,
    mac_vendor: parsed.mac_vendor,
    traceroute: parsed.traceroute,
    scripts: parsed.scripts,
    raw_output: parsed.raw_output,
    scan_source: `local-nmap-${parsed.ip_type}`,
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
        `MERGE (d:Device {ip: $ip})
         ON CREATE SET d.hostname=$hostname, d.ip_type=$ipType, d.first_seen=$ts, d.os=$os
         ON MATCH  SET d.last_seen=$ts, d.ip_type=$ipType, d.os=$os
         WITH d
         MERGE (p:Port {number: $portNum, protocol: $protocol})
         ON CREATE SET p.state = $state
         WITH d, p
         MERGE (s:Service {name: $service, version: $version})
         MERGE (d)-[:HAS_PORT]->(p)
         MERGE (p)-[:RUNS]->(s)`,
        {
          ip: parsed.ip, hostname: parsed.hostname, ipType: parsed.ip_type,
          ts: new Date().toISOString(), os: parsed.os || "unknown",
          portNum: port.number, protocol: port.protocol, state: port.state,
          service: port.service || "unknown", version: port.version || "",
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
  const ttl = (parsed.ip_type === "private" || parsed.ip_type === "loopback") ? 1800 : 3600;
  await redis.set(hostKey, String(parsed.risk_score), { EX: ttl });
  if (parsed.open_count > 0) {
    await redis.zAdd("hot:iocs", [{ score: parsed.risk_score, value: parsed.ip }]);
  }
  return { key: hostKey, score: parsed.risk_score, ttl };
};

const scanIP = async (ip) => {
  if (!ip || typeof ip !== "string") throw new Error("IP or hostname is required");
  const target = ip.trim();
  const { raw, ipType } = await runNmap(target);
  const parsed = parseNmapOutput(raw, target, ipType);
  console.log(`[Nmap] ${ipType.toUpperCase()} scan complete: ${parsed.ports.length} ports, ${parsed.open_count} open, risk=${parsed.risk_score}, os=${parsed.os || "unknown"}`);
  const mongoDoc = await saveToMongo(parsed);
  const neo4jNodes = (parsed.status === "up" && parsed.open_count > 0) ? await saveToNeo4j(parsed) : 0;
  const redisResult = await saveToRedis(parsed);
  return {
    scan: {
      ip: parsed.ip, hostname: parsed.hostname, ip_type: parsed.ip_type, status: parsed.status,
      ports: parsed.ports, open_count: parsed.open_count, risk_score: parsed.risk_score,
      os: parsed.os, os_accuracy: parsed.os_accuracy, latency: parsed.latency,
      mac_address: parsed.mac_address, mac_vendor: parsed.mac_vendor,
      traceroute: parsed.traceroute, scripts: parsed.scripts, scan_ts: parsed.scan_ts,
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

module.exports = { scanIP, getScanHistory, getLatestScan, detectIPType };