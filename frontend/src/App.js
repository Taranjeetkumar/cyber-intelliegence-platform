import { useState } from "react";
import { Provider } from "react-redux";
import { store } from "./app/store";
import { ThemeProvider, useTheme } from "./context/ThemeContext";
import InvestigationPage from "./features/investigation/InvestigationPage";
import IocMonitorPage from "./features/iocMonitor/IocMonitorPage";
import ThreatSearchPage from "./features/threatSearch/ThreatSearchPage";
import { DeviceRiskPage } from "./features/deviceRisk/DeviceRiskPage";
import { IocIngestPage } from "./features/iocIngest/IocIngestPage";
import { CampaignAlertPage } from "./features/campaignAlert/CampaignAlertPage";
import NmapScanPage from "./features/nmapScan/NmapScanPage";

const NAV = [
  { id: "1", label: "Attack Chain", icon: "1", color: "#EF4444" },
  { id: "2", label: "Live Monitor", icon: "2", color: "#22C55E" },
  { id: "3", label: "Threat Search", icon: "3", color: "#3B82F6" },
  { id: "4", label: "Device Risk", icon: "4", color: "#F59E0B" },
  { id: "5", label: "IOC Ingest", icon: "5", color: "#8B5CF6" },
  { id: "6", label: "Campaign Alert", icon: "6", color: "#EF4444" },
  { id: "7", label: "Nmap Scanner", icon: "7", color: "#14B8A6" },
];

// Theme Toggle Component
function ThemeToggle() {
  const { isDark, toggleTheme, theme } = useTheme();

  return (
    <button
      onClick={toggleTheme}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "8px 14px",
        background: isDark ? "rgba(255,255,255,0.1)" : "rgba(0,0,0,0.05)",
        border: `1px solid ${isDark ? "rgba(255,255,255,0.15)" : "rgba(0,0,0,0.1)"}`,
        borderRadius: 8,
        cursor: "pointer",
        transition: "all 0.3s ease",
        color: theme.textPrimary,
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = isDark ? "rgba(255,255,255,0.15)" : "rgba(0,0,0,0.08)";
        e.currentTarget.style.transform = "translateY(-1px)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = isDark ? "rgba(255,255,255,0.1)" : "rgba(0,0,0,0.05)";
        e.currentTarget.style.transform = "translateY(0)";
      }}
    >
      <div style={{
        position: "relative",
        width: 40,
        height: 22,
        background: isDark ? "#334155" : "#E2E8F0",
        borderRadius: 11,
        transition: "all 0.3s ease",
        boxShadow: "inset 0 1px 3px rgba(0,0,0,0.2)",
      }}>
        <div style={{
          position: "absolute",
          top: 2,
          left: isDark ? 20 : 2,
          width: 18,
          height: 18,
          background: isDark ? "#F59E0B" : "#FBBF24",
          borderRadius: "50%",
          transition: "all 0.3s ease",
          boxShadow: isDark
            ? "0 0 10px rgba(245,158,11,0.5)"
            : "0 0 8px rgba(251,191,36,0.6)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}>
          {isDark ? (
            <span style={{ fontSize: 10 }}>🌙</span>
          ) : (
            <span style={{ fontSize: 10 }}>☀️</span>
          )}
        </div>
      </div>
      <span style={{ fontSize: 12, fontWeight: 500 }}>
        {isDark ? "Dark" : "Light"}
      </span>
    </button>
  );
}

// Database Status Indicator
function DatabaseIndicator({ label, port, color, isOnline }) {
  const { theme } = useTheme();

  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "8px 16px",
      transition: "all 0.2s ease",
    }}>
      <div style={{
        position: "relative",
        width: 8,
        height: 8,
      }}>
        <span style={{
          position: "absolute",
          width: 8,
          height: 8,
          borderRadius: "50%",
          background: color,
          animation: isOnline ? "pulse 2s infinite" : "none",
        }} />
        {isOnline && (
          <span style={{
            position: "absolute",
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: color,
            opacity: 0.4,
            animation: "ping 1.5s infinite",
          }} />
        )}
      </div>
      <span style={{ fontSize: 12, color: theme.sidebarTextMuted, flex: 1 }}>{label}</span>
      <span style={{
        fontSize: 10,
        color: theme.sidebarSection,
        fontFamily: "monospace",
        background: "rgba(255,255,255,0.05)",
        padding: "2px 6px",
        borderRadius: 4,
      }}>
        :{port}
      </span>
    </div>
  );
}

function AppContent() {
  const [active, setActive] = useState("1");
  const { theme, isDark } = useTheme();

  const page = {
    1: <InvestigationPage />,
    2: <IocMonitorPage />,
    3: <ThreatSearchPage />,
    4: <DeviceRiskPage />,
    5: <IocIngestPage />,
    6: <CampaignAlertPage />,
    7: <NmapScanPage />,
  }[active];

  const styles = {
    shell: {
      display: "flex",
      height: "100vh",
      overflow: "hidden",
      fontFamily: "'Inter', system-ui, -apple-system, sans-serif",
      background: theme.mainBg,
      transition: "background 0.3s ease",
    },
    sidebar: {
      width: 240,
      background: theme.sidebarBg,
      display: "flex",
      flexDirection: "column",
      padding: "20px 0",
      flexShrink: 0,
      overflowY: "auto",
      borderRight: `1px solid ${theme.sidebarBorder}`,
      transition: "all 0.3s ease",
    },
    logo: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "0 20px 6px"
    },
    logoDot: {
      width: 12,
      height: 12,
      borderRadius: "50%",
      background: `linear-gradient(135deg, ${theme.accent} 0%, #FF6B6B 100%)`,
      boxShadow: `0 0 12px ${theme.accent}50`,
      flexShrink: 0
    },
    logoText: {
      fontSize: 16,
      fontWeight: 700,
      color: theme.sidebarText,
      letterSpacing: "-0.02em",
    },
    logoSub: {
      fontSize: 11,
      color: theme.sidebarTextMuted,
      padding: "0 20px 24px",
      letterSpacing: ".02em"
    },
    navSection: {
      fontSize: 10,
      fontWeight: 600,
      color: theme.sidebarSection,
      letterSpacing: ".12em",
      padding: "16px 20px 8px",
      textTransform: "uppercase",
    },
    navBtn: (isActive, itemColor) => ({
      display: "flex",
      alignItems: "center",
      gap: 12,
      width: "100%",
      padding: "10px 20px",
      border: "none",
      cursor: "pointer",
      transition: "all 0.2s ease",
      textAlign: "left",
      background: isActive
        ? `linear-gradient(90deg, ${itemColor}20 0%, transparent 100%)`
        : "transparent",
      borderLeft: isActive
        ? `3px solid ${itemColor}`
        : "3px solid transparent",
      color: isActive ? itemColor : theme.sidebarTextMuted,
    }),
    navIcon: (isActive, itemColor) => ({
      width: 28,
      height: 28,
      borderRadius: 6,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontSize: 11,
      fontWeight: 700,
      background: isActive
        ? `${itemColor}20`
        : "rgba(255,255,255,0.05)",
      color: isActive ? itemColor : theme.sidebarTextMuted,
      transition: "all 0.2s ease",
    }),
    navLabel: (isActive, itemColor) => ({
      fontSize: 13,
      fontWeight: 500,
      color: isActive ? theme.sidebarText : theme.sidebarTextMuted,
      transition: "color 0.2s ease",
    }),
    sidebarFooter: {
      marginTop: "auto",
      padding: "20px",
      borderTop: `1px solid ${theme.sidebarBorder}`
    },
    footerLine: {
      fontSize: 10,
      color: theme.sidebarSection,
      marginBottom: 4
    },
    main: {
      flex: 1,
      overflowY: "auto",
      background: theme.mainBg,
      transition: "background 0.3s ease",
    },
    header: {
      display: "flex",
      justifyContent: "flex-end",
      alignItems: "center",
      padding: "12px 20px",
      background: isDark ? "rgba(0,0,0,0.2)" : "rgba(255,255,255,0.8)",
      borderBottom: `1px solid ${theme.cardBorder}`,
      backdropFilter: "blur(10px)",
      position: "sticky",
      top: 0,
      zIndex: 100,
    },
  };

  return (
    <div style={styles.shell}>
      {/* Inject keyframe animations */}
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        @keyframes ping {
          0% { transform: scale(1); opacity: 0.4; }
          75%, 100% { transform: scale(2); opacity: 0; }
        }
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
      `}</style>

      {/* ── Sidebar ── */}
      <aside style={styles.sidebar}>
        <div style={styles.logo}>
          <span style={styles.logoDot} />
          <span style={styles.logoText}>CTI Platform</span>
        </div>
        <div style={styles.logoSub}>Cyber Threat Intelligence</div>

        <div style={styles.navSection}>Use Cases</div>
        {NAV.map(n => (
          <button
            key={n.id}
            style={styles.navBtn(active === n.id, n.color)}
            onClick={() => setActive(n.id)}
            onMouseEnter={(e) => {
              if (active !== n.id) {
                e.currentTarget.style.background = "rgba(255,255,255,0.05)";
              }
            }}
            onMouseLeave={(e) => {
              if (active !== n.id) {
                e.currentTarget.style.background = "transparent";
              }
            }}
          >
            <span style={styles.navIcon(active === n.id, n.color)}>{n.icon}</span>
            <span style={styles.navLabel(active === n.id, n.color)}>{n.label}</span>
          </button>
        ))}

        <div style={styles.navSection}>Databases</div>
        <DatabaseIndicator label="MongoDB" port="27017" color={theme.mongoDB} isOnline={true} />
        <DatabaseIndicator label="Redis" port="6379" color={theme.redis} isOnline={true} />
        <DatabaseIndicator label="Neo4j" port="7474" color={theme.neo4j} isOnline={true} />

        <div style={styles.sidebarFooter}>
          <div style={styles.footerLine}>Docker Compose</div>
          <div style={styles.footerLine}>Express + React + Redux</div>
        </div>
      </aside>

      {/* ── Main content ── */}
      <main style={styles.main}>
        <header style={styles.header}>
          <ThemeToggle />
        </header>
        <div style={{ minHeight: "calc(100vh - 56px)" }}>
          {page}
        </div>
      </main>
    </div>
  );
}

function App() {
  return (
    <Provider store={store}>
      <ThemeProvider>
        <AppContent />
      </ThemeProvider>
    </Provider>
  );
}

export default App;
