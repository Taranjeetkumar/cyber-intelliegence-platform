# Cyber Threat Intelligence Platform

## Full Docker SOC + honeypot demo

The Compose stack starts the dashboard, backend, MongoDB, Neo4j, Redis, and three local honeypods:

```powershell
docker compose up --build
```

Open the dashboard:

```txt
http://localhost
```

Generate live captures:

```powershell
ssh fakeuser@localhost -p 2222
curl http://localhost:8080/admin
telnet localhost 2323
```

Captured events are sent to the backend at `/api/honeypot/events`, stored in MongoDB, linked into Neo4j as relationships such as `IP -> TARGETED -> Service`, and counted in Redis under `hot:iocs` and `live:honeypot:events`.

## Prerequisites (install these first)
| Tool | Download |
|------|---------|
| Docker Desktop for Windows | https://www.docker.com/products/docker-desktop/ |
| Node.js 20 LTS | https://nodejs.org/en/download |
| Git | https://git-scm.com/download/win |

Make sure Docker Desktop is **running** before you start.

## Project structure
```
cti-platform/
├── docker-compose.yml        ← starts all 3 databases
├── backend/
│   ├── package.json
│   ├── .env                  ← DB connection strings
│   ├── scripts/
│   │   └── seed.js           ← fills all 3 DBs with sample data
│   └── src/
│       ├── index.js          ← Express entry point
│       ├── config/           ← mongo.js  redis.js  neo4j.js
│       ├── models/           ← IOC.js (Mongoose schema)
│       ├── routes/           ← investigation.js
│       ├── controllers/      ← investigationController.js
│       ├── services/         ← investigationService.js  ← CORE LOGIC
│       └── middleware/       ← errorHandler.js
└── frontend/
    ├── package.json
    └── src/
        ├── app/store.js              ← Redux store
        ├── features/investigation/
        │   ├── investigationSlice.js ← RTK slice + async thunks
        │   └── InvestigationPage.jsx ← main UI page
        └── components/
            ├── graph/
            │   ├── AttackGraph.jsx   ← vis-network graph
            │   └── NodeDetail.jsx    ← click detail panel
            └── ui/
                └── StatBar.jsx
```

---

## Step 1 — Start the databases

Open a terminal in the project root (where docker-compose.yml is):

```powershell
docker-compose up -d
```

Wait about 30 seconds for all three to be healthy. Check:

```powershell
docker-compose ps
```

All three should show **healthy** or **running**.

| Service | UI |
|---------|-----|
| MongoDB | No UI — connect via MongoDB Compass at `mongodb://localhost:27017` |
| Redis   | RedisInsight at http://localhost:8001 |
| Neo4j   | Browser at http://localhost:7474 (user: neo4j / pass: cti_password123) |

---

## Step 2 — Install and seed backend

```powershell
cd backend
npm install
npm run seed
```

You should see:
```
Seeding CTI Platform databases...
MongoDB: 4 IOC records inserted
Neo4j: attack graph built
Redis: counters and sets seeded
All done.
```

---

## Step 3 — Start the backend API

```powershell
npm run dev
```

API is running at http://localhost:5000

---

## Step 4 — Install and start the frontend

Open a **second terminal**:

```powershell
cd frontend
npm install
npm start
```

Browser opens at http://localhost:3000

