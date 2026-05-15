require("dotenv").config();
const mongoose = require("mongoose");
const { createClient } = require("redis");
const neo4j = require("neo4j-driver");
const IOC = require("../src/models/IOC");
const ThreatReport = require("../src/models/ThreatReport");
const Alert = require("../src/models/Alert");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── Connections
const mongoConnect = () => mongoose.connect(process.env.MONGO_URI);

const redisConnect = async () => {
  const client = createClient({ url: process.env.REDIS_URL });
  for (let i = 1; i <= 10; i++) {
    try { await client.connect(); return client; }
    catch { console.log(`  Redis attempt ${i}/10, retrying in 3s...`); await sleep(3000); }
  }
  throw new Error("Redis not ready after 30s");
};

const neo4jConnect = async () => {
  const driver = neo4j.driver(
    process.env.NEO4J_URI,
    neo4j.auth.basic(process.env.NEO4J_USER, process.env.NEO4J_PASSWORD),
    { connectionTimeout: 10000 }
  );
  for (let i = 1; i <= 12; i++) {
    try { await driver.verifyConnectivity(); console.log("  Neo4j ready!"); return driver; }
    catch (e) { console.log(`  Neo4j attempt ${i}/12 (${e.message}), waiting 5s...`); await sleep(5000); }
  }
  throw new Error("Neo4j not ready after 60s");
};

// ── MongoDB data
const iocData = [
  {
    value: "203.0.113.47", type: "ip", tags: ["APT29", "c2", "botnet"], confidence: 92, source: "abuse.ch",
    enrichment: { whois_country: "RU", asn: "AS12345", virustotal_score: "42/72", isp: "Example Hosting Ltd" },
    analyst_notes: "Observed contacting 3 internal hosts over 72h window. Likely C2 server."
  },
  {
    value: "198.51.100.23", type: "ip", tags: ["TA505", "phishing"], confidence: 78, source: "threatfeed-daily",
    enrichment: { whois_country: "CN", asn: "AS67890", virustotal_score: "28/72", isp: "Fast Net Co" }
  },
  {
    value: "10.99.88.77", type: "ip", tags: ["APT28", "lateral-movement"], confidence: 65, source: "internal-ids",
    enrichment: { whois_country: "RU", asn: "AS55555", virustotal_score: "18/72" }
  },
  {
    value: "phishing-kit.ru", type: "domain", tags: ["TA505", "phishing"], confidence: 88, source: "urlhaus",
    enrichment: { whois_country: "RU", asn: "AS11111", virustotal_score: "55/72", isp: "Shady Host LLC" }
  },
  {
    value: "evil-cdn.net", type: "domain", tags: ["APT29", "c2"], confidence: 85, source: "threatfeed-daily",
    enrichment: { whois_country: "RU", asn: "AS22222", virustotal_score: "48/72" }
  },
  {
    value: "malware-drop.xyz", type: "domain", tags: ["ransomware", "c2"], confidence: 91, source: "urlhaus",
    enrichment: { whois_country: "UA", asn: "AS33333", virustotal_score: "61/72" }
  },
  {
    value: "d41d8cd98f00b204e9800998ecf8427e", type: "hash", tags: ["Emotet"], confidence: 95, source: "sandbox",
    enrichment: { virustotal_score: "68/72" }, analyst_notes: "Emotet dropper sample"
  },
];

const reportData = [
  {
    title: "APT29 Cozy Bear Campaign Analysis Q4 2023", source: "internal-threat-team",
    narrative: "APT29 continued to target government and energy sectors using spear-phishing and MSHTML exploits.",
    tags: ["APT29", "spear-phishing", "MSHTML"], iocs: ["203.0.113.47", "evil-cdn.net"], confidence: 90, severity: "critical",
    references: ["https://attack.mitre.org/groups/G0016/"]
  },
  {
    title: "TA505 Phishing Wave — Financial Sector", source: "abuse.ch",
    narrative: "TA505 launched a broad phishing campaign targeting financial institutions using Emotet as initial payload.",
    tags: ["TA505", "Emotet", "phishing", "financial"], iocs: ["198.51.100.23", "phishing-kit.ru"], confidence: 84, severity: "high",
    references: ["https://attack.mitre.org/groups/G0092/"]
  },
  {
    title: "CVE-2021-40444 Active Exploitation Report", source: "nvd",
    narrative: "Multiple threat actors observed exploiting MSHTML RCE vulnerability CVE-2021-40444 in targeted attacks.",
    tags: ["CVE-2021-40444", "MSHTML", "exploit"], iocs: [], confidence: 97, severity: "critical",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-40444"]
  },
  {
    title: "Ransomware Infrastructure — malware-drop.xyz", source: "urlhaus",
    narrative: "Domain used as ransomware dropper staging server. Associated with LockBit.",
    tags: ["ransomware", "LockBit", "c2"], iocs: ["malware-drop.xyz"], confidence: 79, severity: "high"
  },
];

// ── Neo4j graph
const buildGraph = async (driver) => {
  const session = driver.session({ database: "neo4j" });
  await session.run("MATCH (n) DETACH DELETE n");
  console.log("  Graph cleared");

  const queries = [
    `MERGE (i:IP {value:'203.0.113.47'})  SET i.country='RU', i.asn='AS12345', i.confidence=92`,
    `MERGE (i:IP {value:'198.51.100.23'}) SET i.country='CN', i.asn='AS67890', i.confidence=78`,
    `MERGE (i:IP {value:'10.99.88.77'})   SET i.country='RU', i.asn='AS55555', i.confidence=65`,
    `MERGE (d:Domain {value:'phishing-kit.ru'})  SET d.registrar='NameCheap', d.country='RU'`,
    `MERGE (d:Domain {value:'evil-cdn.net'})      SET d.registrar='GoDaddy',   d.country='RU'`,
    `MERGE (d:Domain {value:'malware-drop.xyz'})  SET d.registrar='Namecheap', d.country='UA'`,
    `MERGE (m:Malware {name:'Emotet'})   SET m.family='Emotet',   m.type='trojan'`,
    `MERGE (m:Malware {name:'TrickBot'}) SET m.family='TrickBot', m.type='banking_trojan'`,
    `MERGE (m:Malware {name:'LockBit'})  SET m.family='LockBit',  m.type='ransomware'`,
    `MERGE (c:CVE {cve_id:'CVE-2021-40444'}) SET c.cvss_score=8.8, c.description='MSHTML remote code execution'`,
    `MERGE (c:CVE {cve_id:'CVE-2022-30190'}) SET c.cvss_score=7.8, c.description='Follina MSDT RCE'`,
    `MERGE (c:CVE {cve_id:'CVE-2023-23397'}) SET c.cvss_score=9.8, c.description='Outlook privilege escalation'`,
    `MERGE (e:Exploit {module_name:'exploit/windows/browser/ms_mshtml_rce'})    SET e.platform='Windows', e.reliability='Good'`,
    `MERGE (e:Exploit {module_name:'exploit/windows/msf/follina_msdt'})         SET e.platform='Windows', e.reliability='Excellent'`,
    `MERGE (e:Exploit {module_name:'exploit/windows/smtp/outlook_ntlm_leak'})   SET e.platform='Windows', e.reliability='Normal'`,
    `MERGE (c:Campaign {name:'TA505_Q4_2023'})    SET c.campaign_id='TA505_Q4_2023',    c.start_date='2023-10-01', c.attribution='TA505'`,
    `MERGE (c:Campaign {name:'APT29_NOBELIUM'})   SET c.campaign_id='APT29_NOBELIUM',   c.start_date='2023-06-01', c.attribution='APT29'`,
    `MERGE (c:Campaign {name:'LOCKBIT_WAVE_23'})  SET c.campaign_id='LOCKBIT_WAVE_23',  c.start_date='2023-11-01', c.attribution='LockBit'`,
    `MERGE (a:ThreatActor {name:'TA505'})   SET a.origin_country='RU'`,
    `MERGE (a:ThreatActor {name:'APT29'})   SET a.origin_country='RU'`,
    `MERGE (a:ThreatActor {name:'LockBit'}) SET a.origin_country='RU'`,
    `MERGE (d:Device {hostname:'DESKTOP-HR-01'})  SET d.ip='192.168.1.55', d.os='Windows 10',          d.risk_score=91`,
    `MERGE (d:Device {hostname:'SRV-FILE-02'})    SET d.ip='192.168.1.72', d.os='Windows Server 2019', d.risk_score=76`,
    `MERGE (d:Device {hostname:'WS-FINANCE-03'})  SET d.ip='192.168.1.88', d.os='Windows 11',          d.risk_score=84`,
    `MERGE (p:Port {number:445,  protocol:'TCP'}) SET p.state='open'`,
    `MERGE (p:Port {number:80,   protocol:'TCP'}) SET p.state='open'`,
    `MERGE (p:Port {number:443,  protocol:'TCP'}) SET p.state='open'`,
    `MERGE (svc:Service {name:'SMB',   version:'3.1.1'})`,
    `MERGE (svc:Service {name:'HTTP',  version:'Apache 2.4.49'})`,
    `MERGE (svc:Service {name:'HTTPS', version:'IIS 10.0'})`,
    `MATCH (i:IP {value:'203.0.113.47'}),   (d:Domain {value:'evil-cdn.net'})     MERGE (i)-[:RESOLVES_TO]->(d)`,
    `MATCH (i:IP {value:'198.51.100.23'}),  (d:Domain {value:'phishing-kit.ru'})  MERGE (i)-[:RESOLVES_TO]->(d)`,
    `MATCH (i:IP {value:'10.99.88.77'}),    (d:Domain {value:'malware-drop.xyz'}) MERGE (i)-[:RESOLVES_TO]->(d)`,
    `MATCH (d:Domain {value:'phishing-kit.ru'}), (m:Malware {name:'Emotet'})   MERGE (d)-[:HOSTS]->(m)`,
    `MATCH (d:Domain {value:'evil-cdn.net'}),    (m:Malware {name:'TrickBot'}) MERGE (d)-[:HOSTS]->(m)`,
    `MATCH (d:Domain {value:'malware-drop.xyz'}),(m:Malware {name:'LockBit'})  MERGE (d)-[:HOSTS]->(m)`,
    `MATCH (m:Malware {name:'Emotet'}),   (c:CVE {cve_id:'CVE-2021-40444'}) MERGE (m)-[:EXPLOITS]->(c)`,
    `MATCH (m:Malware {name:'TrickBot'}), (c:CVE {cve_id:'CVE-2022-30190'}) MERGE (m)-[:EXPLOITS]->(c)`,
    `MATCH (m:Malware {name:'LockBit'}),  (c:CVE {cve_id:'CVE-2023-23397'}) MERGE (m)-[:EXPLOITS]->(c)`,
    `MATCH (c:CVE {cve_id:'CVE-2021-40444'}),(e:Exploit {module_name:'exploit/windows/browser/ms_mshtml_rce'}) MERGE (c)-[:HAS_EXPLOIT]->(e)`,
    `MATCH (c:CVE {cve_id:'CVE-2022-30190'}),(e:Exploit {module_name:'exploit/windows/msf/follina_msdt'})      MERGE (c)-[:HAS_EXPLOIT]->(e)`,
    `MATCH (c:CVE {cve_id:'CVE-2023-23397'}),(e:Exploit {module_name:'exploit/windows/smtp/outlook_ntlm_leak'})MERGE (c)-[:HAS_EXPLOIT]->(e)`,
    `MATCH (m:Malware {name:'Emotet'}),   (c:Campaign {name:'TA505_Q4_2023'})   MERGE (m)-[:USED_BY]->(c)`,
    `MATCH (m:Malware {name:'TrickBot'}), (c:Campaign {name:'APT29_NOBELIUM'})  MERGE (m)-[:USED_BY]->(c)`,
    `MATCH (m:Malware {name:'LockBit'}),  (c:Campaign {name:'LOCKBIT_WAVE_23'}) MERGE (m)-[:USED_BY]->(c)`,
    `MATCH (c:Campaign {name:'TA505_Q4_2023'}),   (a:ThreatActor {name:'TA505'})   MERGE (c)-[:OPERATED_BY]->(a)`,
    `MATCH (c:Campaign {name:'APT29_NOBELIUM'}),  (a:ThreatActor {name:'APT29'})   MERGE (c)-[:OPERATED_BY]->(a)`,
    `MATCH (c:Campaign {name:'LOCKBIT_WAVE_23'}),  (a:ThreatActor {name:'LockBit'}) MERGE (c)-[:OPERATED_BY]->(a)`,
    `MATCH (i:IP {value:'203.0.113.47'}),  (d:Device {hostname:'DESKTOP-HR-01'}) MERGE (i)-[:CONTACTED]->(d)`,
    `MATCH (i:IP {value:'198.51.100.23'}), (d:Device {hostname:'SRV-FILE-02'})   MERGE (i)-[:CONTACTED]->(d)`,
    `MATCH (i:IP {value:'10.99.88.77'}),   (d:Device {hostname:'WS-FINANCE-03'}) MERGE (i)-[:CONTACTED]->(d)`,
    `MATCH (dv:Device {hostname:'DESKTOP-HR-01'}), (p:Port {number:445})  MERGE (dv)-[:HAS_PORT]->(p)`,
    `MATCH (dv:Device {hostname:'SRV-FILE-02'}),   (p:Port {number:80})   MERGE (dv)-[:HAS_PORT]->(p)`,
    `MATCH (dv:Device {hostname:'WS-FINANCE-03'}), (p:Port {number:443})  MERGE (dv)-[:HAS_PORT]->(p)`,
    `MATCH (p:Port {number:445}), (svc:Service {name:'SMB'})   MERGE (p)-[:RUNS]->(svc)`,
    `MATCH (p:Port {number:80}),  (svc:Service {name:'HTTP'})  MERGE (p)-[:RUNS]->(svc)`,
    `MATCH (p:Port {number:443}), (svc:Service {name:'HTTPS'}) MERGE (p)-[:RUNS]->(svc)`,
    `MATCH (svc:Service {name:'SMB'}),   (c:CVE {cve_id:'CVE-2021-40444'}) MERGE (svc)-[:VULNERABLE_TO]->(c)`,
    `MATCH (svc:Service {name:'HTTP'}),  (c:CVE {cve_id:'CVE-2022-30190'}) MERGE (svc)-[:VULNERABLE_TO]->(c)`,
    `MATCH (svc:Service {name:'HTTPS'}), (c:CVE {cve_id:'CVE-2023-23397'}) MERGE (svc)-[:VULNERABLE_TO]->(c)`,
  ];

  for (const q of queries) await session.run(q);
  await session.close();
  console.log(`  ${queries.length} Cypher statements executed`);
};

// ── Redis seed
const seedRedis = async (client) => {
  await client.flushDb();

  // Hot IOC leaderboard — these IPs must match nodes in Neo4j graph
  await client.zAdd("hot:iocs", [
    { score: 47, value: "203.0.113.47" },
    { score: 31, value: "198.51.100.23" },
    { score: 22, value: "10.99.88.77" },
    { score: 18, value: "phishing-kit.ru" },
    { score: 9,  value: "evil-cdn.net" },
    { score: 5,  value: "malware-drop.xyz" },
  ]);

  // Device risk TTL scores
  await client.set("risk:host:DESKTOP-HR-01",  "91", { EX: 3600 });
  await client.set("risk:host:SRV-FILE-02",    "76", { EX: 3600 });
  await client.set("risk:host:WS-FINANCE-03",  "84", { EX: 3600 });


  // Ingestion counters
  await client.set("stats:ingested:ip",     "4");
  await client.set("stats:ingested:domain", "3");
  await client.set("stats:ingested:hash",   "1");
  await client.set("stats:ingested:url",    "0");

  console.log("  Redis seeded (campaign:active intentionally empty — run Correlation to populate)");
};

// ── Main
(async () => {
  console.log("Seeding CTI Platform databases...\n");
  console.log("Waiting 5s for containers...\n");
  await sleep(5000);

  await mongoConnect();
  await IOC.deleteMany({});
  await ThreatReport.deleteMany({});
  await Alert.deleteMany({});
  await IOC.insertMany(iocData);
  await ThreatReport.insertMany(reportData);
  console.log(`MongoDB: ${iocData.length} IOCs + ${reportData.length} threat reports inserted`);

  const driver = await neo4jConnect();
  await buildGraph(driver);
  await driver.close();
  console.log("Neo4j: full attack graph built");

  const redis = await redisConnect();
  await seedRedis(redis);
  await redis.disconnect();
  console.log("Redis: counters and sets seeded");

  await mongoose.disconnect();
  console.log("\nAll done! Now run: docker-compose up --build\n");
  process.exit(0);
})().catch((err) => {
  console.error("Seed failed:", err.message);
  process.exit(1);
});