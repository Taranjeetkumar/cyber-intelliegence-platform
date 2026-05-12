import { useState } from "react";
import { Provider } from "react-redux";
import { store } from "./app/store";
import InvestigationPage from "./features/investigation/InvestigationPage";
import IocMonitorPage from "./features/iocMonitor/IocMonitorPage";
import ThreatSearchPage from "./features/threatSearch/ThreatSearchPage";
import { DeviceRiskPage } from "./features/deviceRisk/DeviceRiskPage";
import { IocIngestPage } from "./features/iocIngest/IocIngestPage";
import { CampaignAlertPage } from "./features/campaignAlert/CampaignAlertPage";
import NmapScanPage from "./features/nmapScan/NmapScanPage";

const NAV = [
  { id: "1", label: "Attack Chain", icon: "🔍", db: "", color: "#993C1D" },
  { id: "2", label: "Live Monitor", icon: "📡", db: "", color: "#3B6D11" },
  { id: "3", label: "Threat Search", icon: "🔎", db: "", color: "#185FA5" },
  { id: "4", label: "Device Risk", icon: "⚠️", db: "", color: "#854F0B" },
  { id: "5", label: "IOC Ingest", icon: "📥", db: "", color: "#534AB7" },
  { id: "6", label: "Campaign Alert", icon: "🚨", db: "", color: "#A32D2D" },
  { id: "7", label: "Nmap Scanner", icon: "🔭", db: "local", color: "#0F6E56" },
];

function App() {
  const [active, setActive] = useState("uc1");

  const page = {
    1: <InvestigationPage />,
    2: <IocMonitorPage />,
    3: <ThreatSearchPage />,
    4: <DeviceRiskPage />,
    5: <IocIngestPage />,
    6: <CampaignAlertPage />,
    7: <NmapScanPage />,
  }[active];

  return (
    <Provider store={store}>
      <div style={s.shell}>
        {/* ── Sidebar ── */}
        <aside style={s.sidebar}>
          <div style={s.logo}>
            <span style={s.logoDot} />
            <span style={s.logoText}>CTI Platform</span>
          </div>
          <div style={s.logoSub}>Cyber Threat Intelligence</div>

          <div style={s.navSection}>USE CASES</div>
          {NAV.map(n => (
            <button
              key={n.id}
              style={{
                ...s.navBtn,
                background: active === n.id ? n.color + "18" : "transparent",
                borderLeft: active === n.id ? `3px solid ${n.color}` : "3px solid transparent",
                color: active === n.id ? n.color : "#94A3B8",
              }}
              onClick={() => setActive(n.id)}
            >
              <span style={s.navIcon}>{n.icon}</span>
              <div style={s.navLabels}>
                <span style={{ ...s.navLabel, color: active === n.id ? n.color : "#CBD5E1" }}>{n.label}</span>
                <span style={s.navDb}>{n.db}</span>
              </div>
            </button>
          ))}

          <div style={s.navSection}>DATABASES</div>
          {[
            { label: "MongoDB", port: "27017", color: "#185FA5" },
            { label: "Redis", port: "6379", color: "#A32D2D" },
            { label: "Neo4j", port: "7474", color: "#3B6D11" },
          ].map(db => (
            <div key={db.label} style={s.dbRow}>
              <span style={{ ...s.dbDot, background: db.color }} />
              <span style={s.dbLabel}>{db.label}</span>
              <span style={s.dbPort}>:{db.port}</span>
            </div>
          ))}

          <div style={s.sidebarFooter}>
            <div style={s.footerLine}>Docker Compose</div>
            <div style={s.footerLine}>Express + React + Redux</div>
          </div>
        </aside>

        {/* ── Main content ── */}
        <main style={s.main}>
          {page}
        </main>
      </div>
    </Provider>
  );
}

const s = {
  shell: { display: "flex", height: "100vh", overflow: "hidden", fontFamily: "system-ui,sans-serif" },
  sidebar: {
    width: 220, background: "#0F172A", display: "flex", flexDirection: "column",
    padding: "20px 0", flexShrink: 0, overflowY: "auto"
  },
  logo: { display: "flex", alignItems: "center", gap: 8, padding: "0 16px 4px" },
  logoDot: { width: 10, height: 10, borderRadius: "50%", background: "#A32D2D", flexShrink: 0 },
  logoText: { fontSize: 15, fontWeight: 700, color: "#F1F5F9" },
  logoSub: { fontSize: 10, color: "#475569", padding: "0 16px 20px", letterSpacing: ".04em" },
  navSection: {
    fontSize: 10, fontWeight: 700, color: "#334155", letterSpacing: ".1em",
    padding: "12px 16px 6px", textTransform: "uppercase"
  },
  navBtn: {
    display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "9px 14px",
    border: "none", cursor: "pointer", transition: "all .15s", textAlign: "left"
  },
  navIcon: { fontSize: 14, flexShrink: 0 },
  navLabels: { display: "flex", flexDirection: "column", gap: 1 },
  navLabel: { fontSize: 12, fontWeight: 600, lineHeight: 1.2 },
  navDb: { fontSize: 10, color: "#475569", fontFamily: "monospace" },
  dbRow: { display: "flex", alignItems: "center", gap: 8, padding: "6px 16px" },
  dbDot: { width: 6, height: 6, borderRadius: "50%", flexShrink: 0 },
  dbLabel: { fontSize: 12, color: "#64748B", flex: 1 },
  dbPort: { fontSize: 10, color: "#334155", fontFamily: "monospace" },
  sidebarFooter: { marginTop: "auto", padding: "16px", borderTop: "1px solid #1E293B" },
  footerLine: { fontSize: 10, color: "#334155", marginBottom: 3 },
  main: { flex: 1, overflowY: "auto", background: "#F5F3EE" },
};

export default App;
