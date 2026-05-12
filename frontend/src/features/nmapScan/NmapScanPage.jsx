import { useState, useEffect } from "react";
import axios from "axios";

// ── Colour helpers ────────────────────────────────────────────────────────────
const STATE_STYLE = {
  open: { bg: "#EAF3DE", color: "#27500A", badge: "#3B6D11" },
  open_filtered: { bg: "#EAF3DE", color: "#27500A", badge: "#3B6D11" },
  closed: { bg: "#F5F3EE", color: "#888780", badge: "#B4B2A9" },
  filtered: { bg: "#FAECE7", color: "#712B13", badge: "#993C1D" },
};
const RISK_COLOR = (s) =>
  s >= 80 ? "#A32D2D" : s >= 50 ? "#854F0B" : s >= 20 ? "#534AB7" : "#3B6D11";

const QUICK_TARGETS = ["scanme.nmap.org", "45.33.32.156", "192.168.1.1", "127.0.0.1"];

export default function NmapScanPage() {
  const [ip, setIp] = useState("scanme.nmap.org");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const [nmapReady, setNmapReady] = useState(null); // null=unknown, true/false

  // Live elapsed-time counter shown while scan runs
  useEffect(() => {
    let id;
    if (loading) { setElapsed(0); id = setInterval(() => setElapsed(e => e + 1), 1000); }
    return () => clearInterval(id);
  }, [loading]);

  // Check if Nmap is installed by hitting health endpoint
  useEffect(() => {
    axios.get("/api/health")
      .then(() => setNmapReady(true))
      .catch(() => setNmapReady(false));
  }, []);

  const runScan = async () => {
    if (!ip.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await axios.post("/api/scan/run", { ip: ip.trim() }, { timeout: 130000 });
      setResult(res.data);
      fetchHistory(res.data.scan.ip);
    } catch (err) {
      const msg = err.response?.data?.detail || err.response?.data?.error || "Scan failed";
      const fix = err.response?.data?.fix || null;
      setError({ msg, fix });
    } finally {
      setLoading(false);
    }
  };

  const fetchHistory = async (target) => {
    try {
      const res = await axios.get(`/api/scan/history?ip=${encodeURIComponent(target)}`);
      setHistory(res.data.scans || []);
    } catch { /* silent */ }
  };

  const scan = result?.scan;
  const writes = result?.db_writes;
  const openPorts = scan?.ports?.filter(p => p.state === "open" || p.state === "open_filtered") || [];

  return (
    <div style={s.page}>

      {/* Header */}
      <div style={s.header}>
        <div>
          <h2 style={s.title}>Nmap Port Scanner</h2>
          {/* <p style={s.sub}>Local Nmap binary · Results saved to MongoDB + Neo4j + Redis</p> */}
        </div>
        {/* <div style={s.localBadge}>
          <span style={s.greenDot} />
          Runs locally — no API key, no rate limit
        </div> */}
      </div>

      {/* Install notice */}
      {/* <div style={s.installBox}>
        <div style={s.installTitle}>⚙️ Prerequisite — Nmap must be installed on your Windows machine</div>
        <div style={s.installSteps}>
          <span style={s.installStep}>1. Download: <a href="https://nmap.org/download.html" target="_blank" rel="noreferrer" style={s.link}>nmap.org/download.html</a></span>
          <span style={s.installStep}>2. Run the .exe installer (keep all defaults)</span>
          <span style={s.installStep}>3. Open a new PowerShell and run: <code style={s.code}>nmap --version</code></span>
          <span style={s.installStep}>4. Restart the backend: <code style={s.code}>npm run dev</code></span>
        </div>
      </div> */}

      {/* Input bar */}
      <div style={s.inputBar}>
        <div style={s.inputGroup}>
          <label style={s.label}>Target IP or hostname</label>
          <div style={s.inputRow}>
            <input
              style={s.input}
              value={ip}
              onChange={e => setIp(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !loading && runScan()}
              placeholder="e.g. scanme.nmap.org"
              disabled={loading}
            />
            <button
              style={{ ...s.btn, opacity: loading || !ip.trim() ? 0.55 : 1 }}
              onClick={runScan}
              disabled={loading || !ip.trim()}
            >
              {loading ? `Scanning… ${elapsed}s` : "▶ Scan Now"}
            </button>
          </div>
          <div style={s.quickRow}>
            Quick targets:
            {QUICK_TARGETS.map(t => (
              <button key={t} style={s.quickBtn} onClick={() => setIp(t)} disabled={loading}>{t}</button>
            ))}
          </div>
        </div>

        {/* Pipeline explainer */}
        {/* <div style={s.pipeline}>
          <div style={s.pipelineTitle}>What happens on scan</div>
          {[
            ["#3B6D11", "nmap -sV -T4 run locally"],
            ["#185FA5", "Result saved → MongoDB"],
            ["#3B6D11", "Open ports → Neo4j MERGE"],
            ["#A32D2D", "Risk score → Redis TTL key"],
            ["#534AB7", "UC1 + UC4 updated instantly"],
          ].map(([c, t], i) => (
            <div key={i} style={s.pipelineRow}>
              <span style={{ ...s.pipeDot, background: c }} />
              <span style={s.pipeText}>{t}</span>
            </div>
          ))}
        </div> */}
      </div>

      {/* Loading */}
      {loading && (
        <div style={s.loadingBox}>
          <div style={s.spinnerWrap}>
            <div style={s.spinnerRing} />
          </div>
          <div>
            <div style={s.loadingTitle}>Running Nmap scan… {elapsed}s elapsed</div>
            <div style={s.loadingDetail}>
              Scanning <strong>{ip}</strong> for open ports using local Nmap.
              Typical scan takes 10–30 seconds.
            </div>
            <div style={s.loadingCmd}>
              Command: <code>nmap -sV -T4 --open {ip}</code>
            </div>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={s.errorBox}>
          <div style={s.errorTitle}>⚠ {error.msg}</div>
          {error.fix && (
            <div style={s.errorFix}>
              <strong>How to fix:</strong> {error.fix}
            </div>
          )}
          {error.msg.includes("not installed") || error.msg.includes("not in PATH") ? (
            <div style={s.errorFix}>
              <strong>Steps:</strong>
              <ol style={{ margin: "6px 0 0 16px", lineHeight: 1.8 }}>
                <li>Go to <a href="https://nmap.org/download.html" target="_blank" rel="noreferrer" style={s.link}>nmap.org/download.html</a></li>
                <li>Download "Latest stable release self-installer" (.exe)</li>
                <li>Run the installer, keep all defaults</li>
                <li>Open a new PowerShell: <code>nmap --version</code></li>
                <li>Restart backend: <code>npm run dev</code></li>
              </ol>
            </div>
          ) : null}
        </div>
      )}

      {/* Results */}
      {scan && (
        <div style={s.results}>

          {/* Summary strip */}
          <div style={s.summaryStrip}>
            {[
              { label: "host status", val: scan.status, color: scan.status === "up" ? "#3B6D11" : "#A32D2D" },
              { label: "ports scanned", val: scan.ports.length, color: "#2C2C2A" },
              { label: "open ports", val: openPorts.length, color: "#3B6D11" },
              { label: "risk score", val: scan.risk_score, color: RISK_COLOR(scan.risk_score) },
              { label: "hostname", val: scan.hostname, color: "#185FA5", wide: true },
            ].map(({ label, val, color, wide }) => (
              <div key={label} style={{ ...s.summaryCard, flex: wide ? 2 : 1 }}>
                <div style={{ ...s.summaryVal, color }}>{val}</div>
                <div style={s.summaryKey}>{label}</div>
              </div>
            ))}
          </div>

          <div style={s.resultsGrid}>
            {/* LEFT: port table */}
            <div>
              <div style={s.secTitle}>Port scan results</div>
              <table style={s.table}>
                <thead>
                  <tr>{["Port", "Protocol", "State", "Service", "Version"].map(h => (
                    <th key={h} style={s.th}>{h}</th>
                  ))}</tr>
                </thead>
                <tbody>
                  {scan.ports.length === 0 ? (
                    <tr><td colSpan={5} style={{ ...s.td, textAlign: "center", color: "#888780", fontStyle: "italic" }}>
                      No ports returned. Host may be down or completely firewalled.
                    </td></tr>
                  ) : scan.ports.map((p, i) => {
                    const st = STATE_STYLE[p.state] || STATE_STYLE.closed;
                    return (
                      <tr key={i} style={{ background: st.bg }}>
                        <td style={{ ...s.td, fontFamily: "monospace", fontWeight: 700 }}>{p.number}</td>
                        <td style={{ ...s.td, color: "#5F5E5A" }}>{p.protocol}</td>
                        <td style={s.td}>
                          <span style={{ ...s.badge, background: st.badge }}>{p.state.replace("_", "|")}</span>
                        </td>
                        <td style={{ ...s.td, fontFamily: "monospace" }}>{p.service || "—"}</td>
                        <td style={{ ...s.td, fontSize: 11, color: "#5F5E5A" }}>{p.version || "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>

              {/* Raw output */}
              <details style={{ marginTop: 10 }}>
                <summary style={{ fontSize: 12, color: "#888780", cursor: "pointer", padding: "4px 0" }}>
                  Raw Nmap output
                </summary>
                <pre style={s.rawPre}>{scan.raw_output || "No raw output"}</pre>
              </details>
            </div>

            {/* RIGHT: sidebar */}
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

              {/* DB writes */}
              {/* <div style={s.card}>
                <div style={s.cardTitle}>✅ Database writes</div>
                {[
                  { color: "#185FA5", label: "MongoDB — scan_results", sub: `Doc ID: …${String(writes?.mongodb?.id || "").slice(-8)}` },
                  { color: "#3B6D11", label: "Neo4j — Port+Service nodes", sub: `${writes?.neo4j?.nodes_merged || 0} open port(s) merged` },
                  { color: "#A32D2D", label: `Redis — risk:host:${scan.ip}`, sub: `Score ${writes?.redis?.score} · TTL ${writes?.redis?.ttl}s` },
                ].map(({ color, label, sub }) => (
                  <div key={label} style={s.dbRow}>
                    <span style={{ ...s.dbDot, background: color }} />
                    <div>
                      <div style={s.dbLabel}>{label}</div>
                      <div style={s.dbSub}>{sub}</div>
                    </div>
                  </div>
                ))}
              </div> */}

              {/* Neo4j chains */}
              {/* {openPorts.length > 0 && (
                <div style={s.card}>
                  <div style={s.cardTitle}>Neo4j graph chains created</div>
                  <div style={{ fontSize: 10, color: "#888780", marginBottom: 8 }}>
                    Device → HAS_PORT → Port → RUNS → Service
                  </div>
                  {openPorts.slice(0, 5).map((p, i) => (
                    <div key={i} style={s.chainRow}>
                      <span style={{ ...s.node, background: "#E6F1FB", color: "#0C447C" }}>Device</span>
                      <span style={s.rel}>→ HAS_PORT →</span>
                      <span style={{ ...s.node, background: "#EAF3DE", color: "#27500A" }}>{p.number}/{p.protocol}</span>
                      <span style={s.rel}>→ RUNS →</span>
                      <span style={{ ...s.node, background: "#FAECE7", color: "#712B13" }}>{p.service}</span>
                    </div>
                  ))}
                  {openPorts.length > 5 && (
                    <div style={{ fontSize: 10, color: "#888780", marginTop: 4 }}>
                      + {openPorts.length - 5} more…
                    </div>
                  )}
                  <div style={{ fontSize: 10, color: "#534AB7", marginTop: 8, fontStyle: "italic" }}>
                    These nodes are now visible in UC1 Attack Chain and UC4 Device Risk
                  </div>
                </div>
              )} */}

              {/* Cypher used */}
              {/* <div style={{ ...s.card, background: "#1E1E2E" }}>
                <div style={{ ...s.cardTitle, color: "#CDD6F4" }}>Neo4j Cypher used</div>
                <pre style={s.cypher}>{`MERGE (d:Device {ip: $ip})
ON CREATE SET
  d.hostname = $hostname
ON MATCH SET
  d.last_seen = $ts

MERGE (p:Port {
  number: $portNum,
  protocol: $protocol
})

MERGE (s:Service {
  name: $service,
  version: $version
})

MERGE (d)-[:HAS_PORT]->(p)
MERGE (p)-[:RUNS]->(s)`}</pre>
              </div> */}

              {/* Risk score */}
              {/* <div style={s.card}>
                <div style={s.cardTitle}>Redis risk score</div>
                <div style={{ textAlign: "center", padding: "8px 0" }}>
                  <div style={{ fontSize: 52, fontWeight: 700, fontFamily: "monospace", color: RISK_COLOR(scan.risk_score) }}>
                    {scan.risk_score}
                  </div>
                  <div style={{ fontSize: 11, color: "#888780", marginTop: 2 }}>
                    {scan.open_count} open port(s) × 10 = {scan.risk_score} (max 100)
                  </div>
                  <div style={{ fontFamily: "monospace", fontSize: 11, color: "#5F5E5A", marginTop: 4 }}>
                    risk:host:{scan.ip}  EX 3600
                  </div>
                </div>
              </div> */}

            </div>
          </div>
        </div>
      )}

      {/* Scan history */}
      {history.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <div style={s.secTitle}>Scan history — {history[0]?.ip}</div>
          {history.map((h, i) => (
            <div key={h._id || i} style={s.histRow}>
              <span style={s.histTs}>{new Date(h.scan_ts).toLocaleString()}</span>
              <span style={{ fontFamily: "monospace", fontWeight: 600 }}>{h.ip}</span>
              <span style={{ color: "#3B6D11", fontWeight: 600 }}>{h.open_count} open</span>
              <span style={{ color: "#5F5E5A" }}>{h.ports?.length || 0} total</span>
              <span style={{ color: RISK_COLOR(h.risk_score), fontWeight: 700 }}>risk: {h.risk_score}</span>
              <span style={{ color: "#888780", fontSize: 10 }}>{h.scan_source}</span>
            </div>
          ))}
        </div>
      )}

    </div>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────
const s = {
  page: { padding: 20, fontFamily: "system-ui,sans-serif", maxWidth: 1280, margin: "0 auto" },
  header: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 10 },
  title: { fontSize: 20, fontWeight: 700, color: "#2C2C2A", margin: 0 },
  sub: { fontSize: 12, color: "#888780", margin: "4px 0 0" },
  localBadge: { display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "#27500A", background: "#EAF3DE", border: "1px solid #97C459", padding: "5px 12px", borderRadius: 20, fontWeight: 600 },
  greenDot: { width: 8, height: 8, borderRadius: "50%", background: "#3B6D11", flexShrink: 0 },

  installBox: { background: "#FFFBEB", border: "1px solid #F59E0B", borderRadius: 8, padding: "12px 16px", marginBottom: 16 },
  installTitle: { fontSize: 13, fontWeight: 600, color: "#92400E", marginBottom: 8 },
  installSteps: { display: "flex", gap: 16, flexWrap: "wrap" },
  installStep: { fontSize: 12, color: "#78350F" },
  link: { color: "#185FA5" },
  code: { background: "#1E1E2E", color: "#A6E3A1", padding: "1px 6px", borderRadius: 4, fontFamily: "monospace", fontSize: 11 },

  inputBar: { display: "flex", gap: 16, background: "#F9F8F5", border: "1px solid #D3D1C7", borderRadius: 10, padding: "16px 20px", marginBottom: 20, flexWrap: "wrap" },
  inputGroup: { flex: 1, minWidth: 300 },
  label: { display: "block", fontSize: 11, fontWeight: 600, color: "#5F5E5A", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 6 },
  inputRow: { display: "flex", gap: 10 },
  input: { flex: 1, padding: "9px 12px", fontSize: 14, border: "1px solid #B4B2A9", borderRadius: 6, fontFamily: "monospace", background: "#fff" },
  btn: { padding: "9px 20px", background: "#2E4057", color: "#fff", border: "none", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 700, whiteSpace: "nowrap" },
  quickRow: { marginTop: 8, fontSize: 11, color: "#888780", display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" },
  quickBtn: { background: "#E8E6DF", border: "none", borderRadius: 4, padding: "2px 8px", fontSize: 11, cursor: "pointer", fontFamily: "monospace" },

  pipeline: { minWidth: 220 },
  pipelineTitle: { fontSize: 11, fontWeight: 700, color: "#444441", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 8 },
  pipelineRow: { display: "flex", alignItems: "center", gap: 8, marginBottom: 6 },
  pipeDot: { width: 8, height: 8, borderRadius: "50%", flexShrink: 0 },
  pipeText: { fontSize: 12, color: "#444441" },

  loadingBox: { display: "flex", alignItems: "center", gap: 16, background: "#EEF4FF", border: "1px solid #9DC3F5", borderRadius: 10, padding: "16px 20px", marginBottom: 16 },
  spinnerWrap: { flexShrink: 0 },
  spinnerRing: { width: 32, height: 32, border: "3px solid #CBD8FF", borderTopColor: "#185FA5", borderRadius: "50%", animation: "spin 0.8s linear infinite" },
  loadingTitle: { fontSize: 14, fontWeight: 600, color: "#185FA5" },
  loadingDetail: { fontSize: 12, color: "#444441", marginTop: 4 },
  loadingCmd: { fontSize: 11, color: "#888780", marginTop: 4, fontFamily: "monospace" },

  errorBox: { background: "#FCEBEB", border: "1px solid #F09595", borderRadius: 8, padding: "14px 16px", marginBottom: 16 },
  errorTitle: { fontSize: 13, fontWeight: 600, color: "#791F1F", marginBottom: 6 },
  errorFix: { fontSize: 12, color: "#712B13", marginTop: 6, lineHeight: 1.6 },

  results: { marginTop: 4 },
  summaryStrip: { display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" },
  summaryCard: { flex: 1, background: "#FAFAF8", border: "1px solid #D3D1C7", borderRadius: 8, padding: "10px 12px", textAlign: "center", minWidth: 70 },
  summaryVal: { fontSize: 18, fontWeight: 700, fontFamily: "monospace" },
  summaryKey: { fontSize: 10, color: "#888780", marginTop: 2, textTransform: "uppercase", letterSpacing: ".05em" },

  resultsGrid: { display: "grid", gridTemplateColumns: "1fr 300px", gap: 16, alignItems: "start" },
  secTitle: { fontSize: 12, fontWeight: 700, color: "#5F5E5A", textTransform: "uppercase", letterSpacing: ".07em", marginBottom: 10 },

  table: { width: "100%", borderCollapse: "collapse", fontSize: 13, marginBottom: 8 },
  th: { background: "#2E4057", color: "#fff", padding: "8px 12px", textAlign: "left", fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: ".06em" },
  td: { padding: "7px 12px", borderBottom: "1px solid #E8E6DF" },
  badge: { fontSize: 10, fontWeight: 700, color: "#fff", padding: "2px 8px", borderRadius: 10, textTransform: "uppercase" },
  rawPre: { fontSize: 10, background: "#1E1E2E", color: "#A6E3A1", padding: 12, borderRadius: 6, overflowX: "auto", whiteSpace: "pre-wrap", lineHeight: 1.6, marginTop: 6 },

  card: { background: "#FAFAF8", border: "1px solid #D3D1C7", borderRadius: 10, padding: 14 },
  cardTitle: { fontSize: 11, fontWeight: 700, color: "#444441", marginBottom: 10, textTransform: "uppercase", letterSpacing: ".06em" },
  dbRow: { display: "flex", alignItems: "flex-start", gap: 8, padding: "6px 0", borderBottom: "1px solid #F1EFE8" },
  dbDot: { width: 8, height: 8, borderRadius: "50%", flexShrink: 0, marginTop: 5 },
  dbLabel: { fontSize: 12, fontWeight: 600, color: "#2C2C2A" },
  dbSub: { fontSize: 11, color: "#888780", marginTop: 2 },

  chainRow: { display: "flex", alignItems: "center", gap: 4, flexWrap: "wrap", padding: "4px 0", borderBottom: "1px solid #F1EFE8" },
  node: { fontSize: 10, padding: "2px 7px", borderRadius: 4, fontWeight: 600 },
  rel: { fontSize: 10, color: "#888780" },

  cypher: { fontSize: 10, color: "#A6E3A1", whiteSpace: "pre", lineHeight: 1.7, margin: 0 },

  histRow: { display: "flex", gap: 16, alignItems: "center", background: "#FAFAF8", border: "1px solid #E8E6DF", borderRadius: 6, padding: "8px 14px", fontSize: 12, flexWrap: "wrap", marginBottom: 6 },
  histTs: { color: "#888780", fontFamily: "monospace", fontSize: 11, minWidth: 140 },
};
