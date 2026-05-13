import { useState, useEffect } from "react";
import axios from "axios";

const STATE_STYLE = {
  open: { bg: "#EAF3DE", color: "#27500A", badge: "#3B6D11" },
  open_filtered: { bg: "#EAF3DE", color: "#27500A", badge: "#3B6D11" },
  closed: { bg: "#F5F3EE", color: "#888780", badge: "#B4B2A9" },
  filtered: { bg: "#FAECE7", color: "#712B13", badge: "#993C1D" },
};

const RISK_COLOR = (s) =>
  s >= 80 ? "#A32D2D" : s >= 50 ? "#854F0B" : s >= 20 ? "#534AB7" : "#3B6D11";

const RISK_LABEL = (s) =>
  s >= 80 ? "CRITICAL" : s >= 50 ? "HIGH" : s >= 20 ? "MEDIUM" : "LOW";

const detectIPType = (input) => {
  if (!input) return null;
  const m = input.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return "hostname";
  const [, a, b] = m.map(Number);
  if (a === 127) return "loopback";
  if (a === 10) return "private";
  if (a === 172 && b >= 16 && b <= 31) return "private";
  if (a === 192 && b === 168) return "private";
  if (a === 169 && b === 254) return "private";
  return "public";
};

const IP_TYPE_META = {
  public: { label: "Public IP", color: "#185FA5", bg: "#E6F1FB", flag: "-sV -T4 --open -Pn --traceroute --script=...", note: "-Pn required — public IPs often block ICMP ping" },
  private: { label: "Private IP", color: "#854F0B", bg: "#FFF3E0", flag: "-sV -T4 --open -Pn -n --host-timeout 90s", note: "-Pn skips ping (required for LAN devices)" },
  loopback: { label: "Loopback", color: "#534AB7", bg: "#EDE7F6", flag: "-sV -T4 --open -Pn -n --script=...", note: "Scans the backend server machine itself" },
  hostname: { label: "Hostname", color: "#3B6D11", bg: "#EAF3DE", flag: "-sV -T4 --open -Pn --traceroute --script=...", note: "DNS resolved by Nmap" },
};

const EXAMPLE_GROUPS = [
  { type: "public", label: "Public", targets: ["scanme.nmap.org", "45.33.32.156", "8.8.8.8"] },
  { type: "private", label: "Private", targets: ["192.168.1.1", "192.168.0.1", "10.0.0.1"] },
  { type: "loopback", label: "Loopback", targets: ["127.0.0.1"] },
];

const RISKY_SERVICES = {
  telnet: { severity: "critical", reason: "Cleartext protocol, easily intercepted" },
  ftp: { severity: "high", reason: "Cleartext credentials, use SFTP instead" },
  rdp: { severity: "high", reason: "Common ransomware target, restrict access" },
  vnc: { severity: "high", reason: "Remote desktop — ensure strong auth" },
  smtp: { severity: "medium", reason: "May allow open relay or spam" },
  snmp: { severity: "medium", reason: "Exposes device info, check community strings" },
  http: { severity: "low", reason: "Unencrypted — prefer HTTPS" },
  mysql: { severity: "high", reason: "Database port exposed — should be firewalled" },
  mssql: { severity: "high", reason: "Database port exposed — should be firewalled" },
  mongodb: { severity: "high", reason: "NoSQL DB exposed — ensure auth is required" },
  redis: { severity: "high", reason: "In-memory store exposed — auth should be set" },
  postgres: { severity: "high", reason: "Database port exposed — should be firewalled" },
};

const SEVERITY_COLOR = { critical: "#A32D2D", high: "#854F0B", medium: "#534AB7", low: "#3B6D11" };
const SEVERITY_BG = { critical: "#FCEBEB", high: "#FFF3E0", medium: "#EDE7F6", low: "#EAF3DE" };

export default function NmapScanPage() {
  const [ip, setIp] = useState("scanme.nmap.org");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const [activeTab, setActiveTab] = useState("ports");

  const ipType = detectIPType(ip.trim());
  const typeMeta = IP_TYPE_META[ipType] || null;

  useEffect(() => {
    let id;
    if (loading) {
      setElapsed(0);
      id = setInterval(() => setElapsed(e => e + 1), 1000);
    }
    return () => clearInterval(id);
  }, [loading]);

  const runScan = async () => {
    if (!ip.trim()) return;
    setLoading(true); setError(null); setResult(null); setActiveTab("ports");
    try {
      const res = await axios.post("/api/scan/run", { ip: ip.trim() }, { timeout: 190000 });
      setResult(res.data);
      fetchHistory(res.data.scan.ip);
    } catch (err) {
      const msg = err.response?.data?.detail || err.response?.data?.error || "Scan failed";
      setError(msg);
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

  const secIssues = openPorts
    .map(p => {
      const risk = RISKY_SERVICES[p.service?.toLowerCase()];
      if (risk) return { port: p.number, service: p.service, version: p.version, ...risk };
      return null;
    })
    .filter(Boolean)
    .sort((a, b) => ({ critical: 0, high: 1, medium: 2, low: 3 }[a.severity] - { critical: 0, high: 1, medium: 2, low: 3 }[b.severity]));

  const tabs = [
    { id: "ports", label: `🔌 Ports (${scan?.ports?.length ?? 0})` },
    { id: "security", label: `🛡 Security (${secIssues.length})` }
  ];

  return (
    <div style={s.page}>

      <div style={s.header}>
        <div>
          <h2 style={s.title}>🔭 Nmap Port Scanner</h2>
        </div>

      </div>


      <div style={s.inputBar}>
        <div style={{ flex: 1 }}>
          <label style={s.label}>Target IP or Hostname</label>
          <div style={s.inputRow}>
            <div style={{ flex: 1, position: "relative" }}>
              <input
                style={s.input}
                value={ip}
                onChange={e => setIp(e.target.value)}
                onKeyDown={e => e.key === "Enter" && !loading && runScan()}
                placeholder="e.g. 77.187.36.29 or scanme.nmap.org"
                disabled={loading}
              />
              {typeMeta && (
                <span style={{ ...s.inputBadge, background: typeMeta.bg, color: typeMeta.color, border: `1px solid ${typeMeta.color}44` }}>
                  {typeMeta.label}
                </span>
              )}
            </div>
            <button style={{ ...s.btn, opacity: loading || !ip.trim() ? 0.55 : 1 }} onClick={runScan} disabled={loading || !ip.trim()}>
              {loading ? `⏳ ${elapsed}s…` : "▶ Scan"}
            </button>
          </div>

          <div style={s.quickSection}>
            {EXAMPLE_GROUPS.map(grp => (
              <div key={grp.type} style={s.quickGroup}>
                <span style={{ ...s.quickGroupLabel, color: IP_TYPE_META[grp.type].color }}>{grp.label}:</span>
                {grp.targets.map(t => (
                  <button key={t} style={s.quickBtn} onClick={() => setIp(t)} disabled={loading}>{t}</button>
                ))}
              </div>
            ))}
          </div>

          {ipType === "public" && (
            <div style={{ ...s.infoNote, background: "#E6F1FB", borderColor: "#6AAED6" }}>
              <strong>🌍 Public IP detected</strong>
            </div>
          )}
          {ipType === "private" && (
            <div style={{ ...s.infoNote, background: "#FFF3E0", borderColor: "#EF9F27" }}>
              <strong>📡 Private IP detected</strong>
            </div>
          )}
          {ipType === "loopback" && (
            <div style={{ ...s.infoNote, background: "#EDE7F6", borderColor: "#9B8FD8" }}>
              <strong>🔄 Loopback detected</strong>
            </div>
          )}
        </div>

      </div>

      {loading && (
        <div style={s.loadingBox}>
          <div style={s.spinner} />
          <div>
            <div style={s.loadingTitle}>
              Scanning {ipType === "public" ? "public host" : ipType === "private" ? "LAN device" : "localhost"}: <strong>{ip}</strong> … {elapsed}s
            </div>
            <div style={s.loadingNote}>
              {ipType === "public" ? "Public IPs: service detection + scripts + traceroute. Allow 30–90s."
                : ipType === "private" ? "Private IPs may take longer. Timeout at 90s."
                  : "Localhost: fast, expect results in 5–15s."}
            </div>
            <div style={{ ...s.loadingNote, marginTop: 4 }}>
              <span style={{ display: "inline-block", background: "#CBD8FF", borderRadius: 4, width: 200, height: 6, verticalAlign: "middle" }}>
                <span style={{ display: "block", background: "#185FA5", borderRadius: 4, width: `${Math.min(100, (elapsed / (ipType === "public" ? 60 : 30)) * 100)}%`, height: "100%", transition: "width 1s linear" }} />
              </span>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div style={s.errorBox}>
          <div style={s.errorTitle}>⚠ {error}</div>
          {error.includes("not installed") && (
            <div style={s.errorFix}>
              Install Nmap: <a href="https://nmap.org/download.html" target="_blank" rel="noreferrer" style={{ color: "#185FA5" }}>nmap.org/download.html</a>
              {" → "}install → new PowerShell → <code>nmap --version</code> → restart backend
            </div>
          )}
          {ipType === "public" && (
            <div style={s.errorFix}>
              Tip: -Pn is now used for public IPs. If still 0 results, the host may firewall all ports,
              or nmap needs root/admin on your OS for some scan types.
            </div>
          )}
        </div>
      )}

      {scan && (
        <div style={s.results}>

          <div style={s.summaryStrip}>
            {[
              { label: "IP Type", val: scan.ip_type, color: typeMeta?.color || "#2C2C2A" },
              { label: "Status", val: scan.status, color: scan.status === "up" ? "#3B6D11" : "#A32D2D" },
              { label: "Total Ports", val: scan.ports.length, color: "#2C2C2A" },
              { label: "Open Ports", val: openPorts.length, color: "#3B6D11" },
              { label: "Risk Score", val: `${scan.risk_score} (${RISK_LABEL(scan.risk_score)})`, color: RISK_COLOR(scan.risk_score) },
              { label: "Latency", val: scan.latency != null ? `${(scan.latency * 1000).toFixed(1)} ms` : "—", color: "#5F5E5A" },
              { label: "Target", val: scan.hostname, color: "#185FA5", wide: true },
            ].map(({ label, val, color, wide }) => (
              <div key={label} style={{ ...s.summaryCard, flex: wide ? 2 : 1 }}>
                <div style={{ ...s.summaryVal, color, fontSize: wide ? 13 : 17 }}>{val}</div>
                <div style={s.summaryKey}>{label}</div>
              </div>
            ))}
          </div>

          {(scan.os || scan.mac_address || scan.latency != null) && (
            <div style={s.osStrip}>
              {scan.os && (
                <div style={s.osChip}>
                  <span style={s.osIcon}>💻</span>
                  <div>
                    <div style={s.osLabel}>OS Detection</div>
                    <div style={s.osVal}>{scan.os}{scan.os_accuracy ? ` (${scan.os_accuracy}% confidence)` : ""}</div>
                  </div>
                </div>
              )}
              {scan.mac_address && (
                <div style={s.osChip}>
                  <span style={s.osIcon}>🔌</span>
                  <div>
                    <div style={s.osLabel}>MAC Address</div>
                    <div style={s.osVal}>{scan.mac_address}{scan.mac_vendor ? ` · ${scan.mac_vendor}` : ""}</div>
                  </div>
                </div>
              )}
              {scan.latency != null && (
                <div style={s.osChip}>
                  <span style={s.osIcon}>⏱</span>
                  <div>
                    <div style={s.osLabel}>Round-Trip Latency</div>
                    <div style={s.osVal}>{(scan.latency * 1000).toFixed(2)} ms</div>
                  </div>
                </div>
              )}
            </div>
          )}

          <div style={s.tabBar}>
            {tabs.map(t => (
              <button key={t.id} style={{ ...s.tab, ...(activeTab === t.id ? s.tabActive : {}) }} onClick={() => setActiveTab(t.id)}>
                {t.label}
              </button>
            ))}
          </div>

          {activeTab === "ports" && (
            <table style={s.table}>
              <thead>
                <tr>{["Port", "Protocol", "State", "Service", "Version", "Scripts"].map(h => <th key={h} style={s.th}>{h}</th>)}</tr>
              </thead>
              <tbody>
                {scan.ports.length === 0 ? (
                  <tr><td colSpan={6} style={{ ...s.td, textAlign: "center", color: "#888780", fontStyle: "italic", padding: 20 }}>
                    {scan.status === "down" ? "Host appears down or all ports filtered." : "No ports returned — host may firewall all ports."}
                  </td></tr>
                ) : scan.ports.map((p, i) => {
                  const st = STATE_STYLE[p.state] || STATE_STYLE.closed;
                  return (
                    <tr key={i} style={{ background: st.bg }}>
                      <td style={{ ...s.td, fontFamily: "monospace", fontWeight: 700 }}>{p.number}</td>
                      <td style={{ ...s.td, color: "#5F5E5A" }}>{p.protocol}</td>
                      <td style={s.td}><span style={{ ...s.badge, background: st.badge }}>{p.state.replace("_", "|")}</span></td>
                      <td style={{ ...s.td, fontFamily: "monospace" }}>{p.service || "—"}</td>
                      <td style={{ ...s.td, fontSize: 11, color: "#5F5E5A" }}>{p.version || "—"}</td>
                      <td style={{ ...s.td, fontSize: 10, color: "#534AB7" }}>{Object.keys(p.scripts || {}).join(", ") || "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}

          {activeTab === "security" && (
            <div>
              <div style={s.riskGaugeWrap}>
                <div style={s.riskGauge}>
                  <div style={{ ...s.riskFill, width: `${scan.risk_score}%`, background: RISK_COLOR(scan.risk_score) }} />
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 8 }}>
                  <span style={{ fontSize: 32, fontWeight: 800, fontFamily: "monospace", color: RISK_COLOR(scan.risk_score) }}>{scan.risk_score}</span>
                  <div>
                    <div style={{ fontWeight: 700, color: RISK_COLOR(scan.risk_score) }}>{RISK_LABEL(scan.risk_score)} RISK</div>
                    <div style={{ fontSize: 11, color: "#888780" }}>Based on open port count + service sensitivity</div>
                  </div>
                </div>
              </div>
              {secIssues.length === 0 ? (
                <div style={{ ...s.card, textAlign: "center", color: "#3B6D11", padding: 24 }}>✅ No obviously risky services detected.</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 16 }}>
                  {secIssues.map((issue, i) => (
                    <div key={i} style={{ ...s.secCard, background: SEVERITY_BG[issue.severity], borderColor: SEVERITY_COLOR[issue.severity] }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <span style={{ ...s.sevBadge, background: SEVERITY_COLOR[issue.severity] }}>{issue.severity.toUpperCase()}</span>
                        <span style={{ fontFamily: "monospace", fontWeight: 700, fontSize: 14 }}>:{issue.port}</span>
                        <span style={{ fontWeight: 600 }}>{issue.service}</span>
                        {issue.version && <span style={{ fontSize: 11, color: "#5F5E5A" }}>{issue.version}</span>}
                      </div>
                      <div style={{ marginTop: 6, fontSize: 12, color: "#2C2C2A" }}>⚠ {issue.reason}</div>
                    </div>
                  ))}
                </div>
              )}
              <div style={s.secTitle}>Port Risk Breakdown</div>
              <table style={s.table}>
                <thead><tr>{["Port", "Service", "Base Pts", "Sensitivity Bonus", "Total"].map(h => <th key={h} style={s.th}>{h}</th>)}</tr></thead>
                <tbody>
                  {openPorts.map((p, i) => {
                    const isSensitive = !!RISKY_SERVICES[p.service?.toLowerCase()];
                    const isHighPort = [21, 23, 445, 3389, 5900, 161, 1433, 3306, 5432, 27017].includes(p.number);
                    const base = (scan.ip_type === "private" || scan.ip_type === "loopback") ? 15 : 10;
                    const bonus = (isSensitive ? 20 : 0) + (isHighPort ? 15 : 0);
                    return (
                      <tr key={i}>
                        <td style={{ ...s.td, fontFamily: "monospace", fontWeight: 700 }}>{p.number}</td>
                        <td style={{ ...s.td, fontFamily: "monospace" }}>{p.service || "—"}</td>
                        <td style={s.td}>{base}</td>
                        <td style={{ ...s.td, color: bonus ? "#A32D2D" : "#888780" }}>{bonus > 0 ? `+${bonus}` : "—"}</td>
                        <td style={{ ...s.td, fontWeight: 700, color: RISK_COLOR(base + bonus) }}>{base + bonus}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}


        </div>
      )}

      {history.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <div style={s.secTitle}>Scan History — {history[0]?.ip}</div>
          {history.map((h, i) => (
            <div key={h._id || i} style={s.histRow}>
              <span style={s.histTs}>{new Date(h.scan_ts).toLocaleString()}</span>
              <span style={{ fontFamily: "monospace", fontWeight: 600 }}>{h.ip}</span>
              <span style={{ fontSize: 10, background: "#F1EFE8", padding: "1px 6px", borderRadius: 4 }}>{h.scan_source?.replace("local-nmap-", "") || "nmap"}</span>
              {h.os && <span style={{ fontSize: 11, color: "#534AB7" }}>💻 {h.os.substring(0, 30)}</span>}
              <span style={{ color: "#3B6D11", fontWeight: 600 }}>{h.open_count} open</span>
              <span style={{ color: RISK_COLOR(h.risk_score), fontWeight: 700 }}>risk: {h.risk_score}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const s = {
  page: { padding: 20, fontFamily: "system-ui,sans-serif", maxWidth: 1280, margin: "0 auto" },
  header: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 10 },
  title: { fontSize: 20, fontWeight: 700, color: "#2C2C2A", margin: 0 },
  sub: { fontSize: 12, color: "#888780", margin: "4px 0 0" },
  fixBadge: { display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "#27500A", background: "#EAF3DE", border: "1px solid #97C459", padding: "5px 12px", borderRadius: 20, fontWeight: 600 },
  dot: { width: 8, height: 8, borderRadius: "50%", flexShrink: 0 },
  typeExplainer: { background: "#F9F8F5", border: "1px solid #D3D1C7", borderRadius: 10, padding: "14px 16px", marginBottom: 16 },
  explainerTitle: { fontSize: 12, fontWeight: 700, color: "#444441", textTransform: "uppercase", letterSpacing: ".07em", marginBottom: 10 },
  typeGrid: { display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 8 },
  typeCard: { border: "1.5px solid", borderRadius: 8, padding: "10px 12px" },
  typeLabel: { fontSize: 12, fontWeight: 700, marginBottom: 4 },
  typeFlag: { fontFamily: "monospace", fontSize: 10, color: "#2C2C2A", marginBottom: 4, wordBreak: "break-all" },
  typeNote: { fontSize: 10, color: "#5F5E5A" },
  inputBar: { display: "flex", gap: 16, background: "#F9F8F5", border: "1px solid #D3D1C7", borderRadius: 10, padding: "16px 20px", marginBottom: 16, flexWrap: "wrap" },
  label: { display: "block", fontSize: 11, fontWeight: 600, color: "#5F5E5A", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 6 },
  inputRow: { display: "flex", gap: 10 },
  input: { width: "100%", padding: "9px 12px", fontSize: 14, border: "1px solid #B4B2A9", borderRadius: 6, fontFamily: "monospace", background: "#fff", boxSizing: "border-box" },
  inputBadge: { position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 10, pointerEvents: "none" },
  btn: { padding: "9px 20px", background: "#2E4057", color: "#fff", border: "none", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 700, whiteSpace: "nowrap" },
  quickSection: { marginTop: 10, display: "flex", gap: 16, flexWrap: "wrap" },
  quickGroup: { display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" },
  quickGroupLabel: { fontSize: 11, fontWeight: 700 },
  quickBtn: { background: "#E8E6DF", border: "none", borderRadius: 4, padding: "2px 8px", fontSize: 11, cursor: "pointer", fontFamily: "monospace" },
  infoNote: { marginTop: 10, border: "1px solid", borderRadius: 6, padding: "10px 12px", fontSize: 12, lineHeight: 1.6 },
  code: { background: "#1E1E2E", color: "#A6E3A1", padding: "1px 5px", borderRadius: 3, fontFamily: "monospace", fontSize: 11 },
  flagsPanel: { minWidth: 260, background: "#1E1E2E", borderRadius: 10, padding: 14 },
  flagsTitle: { fontSize: 11, fontWeight: 700, color: "#CDD6F4", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 8 },
  flagsCmd: { fontFamily: "monospace", fontSize: 12, color: "#A6E3A1", marginBottom: 10, lineHeight: 1.6, wordBreak: "break-all" },
  flagsBreakdown: { display: "flex", flexDirection: "column", gap: 5 },
  flagRow: { display: "flex", alignItems: "center", gap: 8 },
  flagCode: { fontSize: 11, background: "#313244", color: "#89B4FA", padding: "1px 7px", borderRadius: 4, fontFamily: "monospace", flexShrink: 0 },
  flagDesc: { fontSize: 11, color: "#6C7086" },
  loadingBox: { display: "flex", alignItems: "center", gap: 16, background: "#EEF4FF", border: "1px solid #9DC3F5", borderRadius: 10, padding: "14px 18px", marginBottom: 16 },
  spinner: { width: 28, height: 28, border: "3px solid #CBD8FF", borderTopColor: "#185FA5", borderRadius: "50%", flexShrink: 0, animation: "spin 0.8s linear infinite" },
  loadingTitle: { fontSize: 13, fontWeight: 600, color: "#185FA5" },
  loadingNote: { fontSize: 11, color: "#444441", marginTop: 4 },
  errorBox: { background: "#FCEBEB", border: "1px solid #F09595", borderRadius: 8, padding: "12px 16px", marginBottom: 16 },
  errorTitle: { fontSize: 13, fontWeight: 600, color: "#791F1F", marginBottom: 4 },
  errorFix: { fontSize: 12, color: "#712B13", lineHeight: 1.6 },
  results: { marginTop: 4 },
  summaryStrip: { display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" },
  summaryCard: { flex: 1, background: "#FAFAF8", border: "1px solid #D3D1C7", borderRadius: 8, padding: "10px 12px", textAlign: "center", minWidth: 70 },
  summaryVal: { fontSize: 17, fontWeight: 700, fontFamily: "monospace" },
  summaryKey: { fontSize: 10, color: "#888780", marginTop: 2, textTransform: "uppercase", letterSpacing: ".05em" },
  osStrip: { display: "flex", gap: 12, marginBottom: 12, flexWrap: "wrap" },
  osChip: { display: "flex", alignItems: "center", gap: 10, background: "#F9F8F5", border: "1px solid #D3D1C7", borderRadius: 8, padding: "8px 14px" },
  osIcon: { fontSize: 20 },
  osLabel: { fontSize: 10, color: "#888780", textTransform: "uppercase", letterSpacing: ".06em" },
  osVal: { fontSize: 13, fontWeight: 600, color: "#2C2C2A", fontFamily: "monospace" },
  tabBar: { display: "flex", gap: 4, borderBottom: "2px solid #E8E6DF", marginBottom: 14, flexWrap: "wrap" },
  tab: { padding: "8px 14px", fontSize: 12, fontWeight: 600, border: "none", background: "none", cursor: "pointer", color: "#888780", borderBottom: "2px solid transparent", marginBottom: -2 },
  tabActive: { color: "#185FA5", borderBottom: "2px solid #185FA5", background: "#F0F7FF", borderRadius: "6px 6px 0 0" },
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
  secTitle: { fontSize: 12, fontWeight: 700, color: "#5F5E5A", textTransform: "uppercase", letterSpacing: ".07em", marginBottom: 10 },
  secCard: { border: "1.5px solid", borderRadius: 8, padding: "10px 14px" },
  sevBadge: { fontSize: 10, fontWeight: 800, color: "#fff", padding: "2px 8px", borderRadius: 4, textTransform: "uppercase", letterSpacing: ".05em" },
  riskGaugeWrap: { background: "#FAFAF8", border: "1px solid #D3D1C7", borderRadius: 10, padding: 16, marginBottom: 16 },
  riskGauge: { height: 12, background: "#E8E6DF", borderRadius: 6, overflow: "hidden" },
  riskFill: { height: "100%", borderRadius: 6, transition: "width 0.5s ease" },
  chainRow: { display: "flex", alignItems: "center", gap: 4, flexWrap: "wrap", padding: "6px 0", borderBottom: "1px solid #F1EFE8", fontSize: 11 },
  node: { fontSize: 10, padding: "3px 8px", borderRadius: 4, fontWeight: 600, fontFamily: "monospace" },
  rel: { fontSize: 10, color: "#888780", fontStyle: "italic" },
  cypher: { fontSize: 10, color: "#A6E3A1", whiteSpace: "pre", lineHeight: 1.7, margin: 0 },
  histRow: { display: "flex", gap: 14, alignItems: "center", background: "#FAFAF8", border: "1px solid #E8E6DF", borderRadius: 6, padding: "8px 14px", fontSize: 12, flexWrap: "wrap", marginBottom: 6 },
  histTs: { color: "#888780", fontFamily: "monospace", fontSize: 11, minWidth: 140 },
};