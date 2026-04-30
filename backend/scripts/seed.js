require("dotenv").config();
const mongoose = require("mongoose");
const { createClient } = require("redis");
const neo4j = require("neo4j-driver");
const IOC = require("../src/models/IOC");

const mongoConnect = () => mongoose.connect(process.env.MONGO_URI);

const redisConnect = async () => {
  const client = createClient({ url: process.env.REDIS_URL });
  await client.connect();
  return client;
};

const neo4jConnect = () =>
  neo4j.driver(
    process.env.NEO4J_URI,
    neo4j.auth.basic(process.env.NEO4J_USER, process.env.NEO4J_PASSWORD)
  );

// MongoDB seed data
const iocData = [
  {
    value: "203.0.113.47",
    type: "ip",
    tags: ["APT29", "c2", "botnet"],
    confidence: 92,
    source: "abuse.ch",
    enrichment: {
      whois_country: "RU",
      asn: "AS12345",
      virustotal_score: "42/72",
      isp: "Example Hosting Ltd",
    },
    analyst_notes: "Observed contacting 3 internal hosts over 72h window. Likely C2.",
  },
  {
    value: "198.51.100.23",
    type: "ip",
    tags: ["TA505", "phishing"],
    confidence: 78,
    source: "threatfeed-daily",
    enrichment: {
      whois_country: "CN",
      asn: "AS67890",
      virustotal_score: "28/72",
      isp: "Fast Net Co",
    },
    analyst_notes: "Linked to TA505 phishing campaign Q4.",
  },
  {
    value: "phishing-kit.ru",
    type: "domain",
    tags: ["TA505", "phishing"],
    confidence: 88,
    source: "urlhaus",
    enrichment: {
      whois_country: "RU",
      asn: "AS11111",
      virustotal_score: "55/72",
      isp: "Shady Host LLC",
    },
  },
  {
    value: "evil-cdn.net",
    type: "domain",
    tags: ["APT29", "c2"],
    confidence: 85,
    source: "threatfeed-daily",
    enrichment: {
      whois_country: "RU",
      asn: "AS22222",
      virustotal_score: "48/72",
    },
  },
];

// ── Neo4j seed: complete attack graph ──────────────────────────────────────
// Graph: IP → Domain → Malware → CVE → Exploit
//              ↓
//           Campaign → ThreatActor
//              ↓
//           Device (victim)
const buildGraph = async (driver) => {
  const session = driver.session({ database: "neo4j" });

  // Clear existing data so seed is idempotent
  await session.run("MATCH (n) DETACH DELETE n");
  console.log("  Graph cleared");

  const queries = [
    // IPs
    `MERGE (i:IP {value: '203.0.113.47'})
     SET i.country='RU', i.asn='AS12345', i.confidence=92`,

    `MERGE (i:IP {value: '198.51.100.23'})
     SET i.country='CN', i.asn='AS67890', i.confidence=78`,

    // Domains
    `MERGE (d:Domain {value: 'phishing-kit.ru'})
     SET d.registrar='NameCheap', d.country='RU'`,

    `MERGE (d:Domain {value: 'evil-cdn.net'})
     SET d.registrar='GoDaddy', d.country='RU'`,

    // Malware
    `MERGE (m:Malware {name: 'Emotet'})
     SET m.family='Emotet', m.type='trojan'`,

    `MERGE (m:Malware {name: 'TrickBot'})
     SET m.family='TrickBot', m.type='banking_trojan'`,

    // CVEs
    `MERGE (c:CVE {cve_id: 'CVE-2021-40444'})
     SET c.cvss_score=8.8, c.description='MSHTML remote code execution'`,

    `MERGE (c:CVE {cve_id: 'CVE-2022-30190'})
     SET c.cvss_score=7.8, c.description='Microsoft Support Diagnostic Tool RCE'`,

    // Exploits
    `MERGE (e:Exploit {module_name: 'exploit/windows/browser/ms_mshtml_rce'})
     SET e.platform='Windows', e.reliability='Good'`,

    `MERGE (e:Exploit {module_name: 'exploit/windows/msf/follina_msdt'})
     SET e.platform='Windows', e.reliability='Excellent'`,

    // Campaigns
    `MERGE (camp:Campaign {name: 'TA505_Q4_2023'})
     SET camp.campaign_id='TA505_Q4_2023', camp.start_date='2023-10-01', camp.attribution='TA505'`,

    `MERGE (camp:Campaign {name: 'APT29_NOBELIUM'})
     SET camp.campaign_id='APT29_NOBELIUM', camp.start_date='2023-06-01', camp.attribution='APT29'`,

    // Threat actors
    `MERGE (a:ThreatActor {name: 'TA505'})
     SET a.aliases=['Hive0065','Evil Corp'], a.origin_country='RU'`,

    `MERGE (a:ThreatActor {name: 'APT29'})
     SET a.aliases=['Cozy Bear','Midnight Blizzard'], a.origin_country='RU'`,

    // Victim devices
    `MERGE (d:Device {hostname: 'DESKTOP-HR-01'})
     SET d.ip='192.168.1.55', d.os='Windows 10', d.risk_score=91`,

    `MERGE (d:Device {hostname: 'SRV-FILE-02'})
     SET d.ip='192.168.1.72', d.os='Windows Server 2019', d.risk_score=76`,

    // Ports & services
    `MERGE (p:Port {number: 445, protocol: 'TCP'})
     SET p.state='open'`,

    `MERGE (p:Port {number: 80, protocol: 'TCP'})
     SET p.state='open'`,

    `MERGE (svc:Service {name: 'SMB', version: '3.1.1'})`,
    `MERGE (svc:Service {name: 'HTTP', version: 'Apache 2.4.49'})`,

    // ── Relationships ───────────────────────────────────────────────────────
    // IP → Domain
    `MATCH (i:IP {value:'203.0.113.47'}), (d:Domain {value:'evil-cdn.net'})
     MERGE (i)-[:RESOLVES_TO]->(d)`,

    `MATCH (i:IP {value:'198.51.100.23'}), (d:Domain {value:'phishing-kit.ru'})
     MERGE (i)-[:RESOLVES_TO]->(d)`,

    // Domain → Malware
    `MATCH (d:Domain {value:'phishing-kit.ru'}), (m:Malware {name:'Emotet'})
     MERGE (d)-[:HOSTS]->(m)`,

    `MATCH (d:Domain {value:'evil-cdn.net'}), (m:Malware {name:'TrickBot'})
     MERGE (d)-[:HOSTS]->(m)`,

    // Malware → CVE
    `MATCH (m:Malware {name:'Emotet'}), (c:CVE {cve_id:'CVE-2021-40444'})
     MERGE (m)-[:EXPLOITS]->(c)`,

    `MATCH (m:Malware {name:'TrickBot'}), (c:CVE {cve_id:'CVE-2022-30190'})
     MERGE (m)-[:EXPLOITS]->(c)`,

    // CVE → Exploit
    `MATCH (c:CVE {cve_id:'CVE-2021-40444'}), (e:Exploit {module_name:'exploit/windows/browser/ms_mshtml_rce'})
     MERGE (c)-[:HAS_EXPLOIT]->(e)`,

    `MATCH (c:CVE {cve_id:'CVE-2022-30190'}), (e:Exploit {module_name:'exploit/windows/msf/follina_msdt'})
     MERGE (c)-[:HAS_EXPLOIT]->(e)`,

    // Malware → Campaign
    `MATCH (m:Malware {name:'Emotet'}), (camp:Campaign {name:'TA505_Q4_2023'})
     MERGE (m)-[:USED_BY]->(camp)`,

    `MATCH (m:Malware {name:'TrickBot'}), (camp:Campaign {name:'APT29_NOBELIUM'})
     MERGE (m)-[:USED_BY]->(camp)`,

    // Campaign → ThreatActor
    `MATCH (camp:Campaign {name:'TA505_Q4_2023'}), (a:ThreatActor {name:'TA505'})
     MERGE (camp)-[:OPERATED_BY]->(a)`,

    `MATCH (camp:Campaign {name:'APT29_NOBELIUM'}), (a:ThreatActor {name:'APT29'})
     MERGE (camp)-[:OPERATED_BY]->(a)`,

    // IP → Device (contacted)
    `MATCH (i:IP {value:'203.0.113.47'}), (d:Device {hostname:'DESKTOP-HR-01'})
     MERGE (i)-[:CONTACTED]->(d)`,

    `MATCH (i:IP {value:'198.51.100.23'}), (d:Device {hostname:'SRV-FILE-02'})
     MERGE (i)-[:CONTACTED]->(d)`,

    // Device → Port → Service → CVE
    `MATCH (dev:Device {hostname:'DESKTOP-HR-01'}), (p:Port {number:445})
     MERGE (dev)-[:HAS_PORT]->(p)`,

    `MATCH (p:Port {number:445}), (svc:Service {name:'SMB'})
     MERGE (p)-[:RUNS]->(svc)`,

    `MATCH (svc:Service {name:'SMB'}), (c:CVE {cve_id:'CVE-2021-40444'})
     MERGE (svc)-[:VULNERABLE_TO]->(c)`,
  ];

  for (const q of queries) {
    await session.run(q);
  }

  await session.close();
  console.log(`  ${queries.length} Cypher statements executed`);
};

// Redis seed
const seedRedis = async (client) => {
  await client.flushDb();

  // Hot IOC leaderboard
  await client.zAdd("hot:iocs", [
    { score: 47, value: "203.0.113.47" },
    { score: 31, value: "198.51.100.23" },
    { score: 18, value: "phishing-kit.ru" },
    { score: 9, value: "evil-cdn.net" },
  ]);

  // Device risk scores
  await client.set("risk:host:DESKTOP-HR-01", "91", { EX: 3600 });
  await client.set("risk:host:SRV-FILE-02", "76", { EX: 3600 });

  // Active campaigns
  await client.sAdd("campaign:active", ["TA505_Q4_2023", "APT29_NOBELIUM"]);

  console.log("  Redis seeded: hot:iocs, risk scores, active campaigns");
};

(async () => {
  console.log("Seeding CTI Platform databases...");

  // MongoDB
  await mongoConnect();
  await IOC.deleteMany({});
  await IOC.insertMany(iocData);
  console.log(`MongoDB: ${iocData.length} IOC records inserted`);

  // Neo4j
  const driver = neo4jConnect();
  await buildGraph(driver);
  await driver.close();
  console.log("Neo4j: attack graph built");

  // Redis
  const redis = await redisConnect();
  await seedRedis(redis);
  await redis.disconnect();
  console.log("Redis: counters and sets seeded");

  await mongoose.disconnect();
  process.exit(0);
})().catch((err) => {
  console.error("Seed failed:", err);
  process.exit(1);
});
