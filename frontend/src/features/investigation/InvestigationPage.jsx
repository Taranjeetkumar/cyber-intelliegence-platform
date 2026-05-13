import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
  fetchKnownIPs,
  investigateIP,
  setSelectedIP,
  clearResult,
  selectKnownIPs,
  selectSelectedIP,
  selectResult,
  selectSelectedNode,
  selectStatus,
  selectError,
} from "../../features/investigation/investigationSlice";
import AttackGraph from "../../components/graph/AttackGraph";
import NodeDetail from "../../components/graph/NodeDetail";
import StatBar from "../../components/ui/StatBar";

const InvestigationPage = () => {
  const dispatch = useDispatch();
  const knownIPs = useSelector(selectKnownIPs);
  const selectedIP = useSelector(selectSelectedIP);
  const result = useSelector(selectResult);
  const selectedNode = useSelector(selectSelectedNode);
  const status = useSelector(selectStatus);
  const error = useSelector(selectError);

  // Load dropdown options on mount
  useEffect(() => {
    dispatch(fetchKnownIPs());
  }, [dispatch]);

  const handleInvestigate = () => {
    if (selectedIP) dispatch(investigateIP(selectedIP));
  };

  const handleClear = () => dispatch(clearResult());

  return (
    <div style={styles.page}>
      {/* ── Header ─────────────────────────────────────────── */}
      <header style={styles.header}>
        <div>
          <h1 style={styles.h1}>
            <span style={styles.dot} />
            CTI Platform
          </h1>
          <p style={styles.sub}>Cyber Threat Intelligence · Attack Chain Investigation</p>
        </div>
        <div style={styles.dbPills}>
          <Pill color="#185FA5" label="MongoDB" />
          <Pill color="#3B6D11" label="Redis" />
          <Pill color="#993C1D" label="Neo4j" />
        </div>
      </header>

      {/* ── Search bar ─────────────────────────────────────── */}
      <div style={styles.searchBar}>
        <div style={styles.searchInner}>
          <label style={styles.searchLabel}>Select suspicious IP</label>
          <div style={styles.searchRow}>
            <select
              style={styles.select}
              value={selectedIP}
              onChange={(e) => dispatch(setSelectedIP(e.target.value))}
            >
              <option value="">-- choose an IP --</option>
              {knownIPs.map((ip) => (
                <option key={ip} value={ip}>{ip}</option>
              ))}
            </select>
            <button
              style={{
                ...styles.btn,
                opacity: status === "loading" || !selectedIP ? 0.5 : 1,
                cursor: status === "loading" || !selectedIP ? "not-allowed" : "pointer",
              }}
              onClick={handleInvestigate}
              disabled={status === "loading" || !selectedIP}
            >
              {status === "loading" ? "Investigating…" : "Investigate →"}
            </button>
            {result && (
              <button style={styles.btnGhost} onClick={handleClear}>
                Clear
              </button>
            )}
          </div>
        </div>

        
      </div>

      {/* ── Error ──────────────────────────────────────────── */}
      {error && (
        <div style={styles.errorBox}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* ── Results ────────────────────────────────────────── */}
      {result && result.found && (
        <>
          <StatBar stats={result.stats} activeCampaigns={result.activeCampaigns} />

          <div style={styles.resultGrid}>
            {/* Left: graph */}
            <div style={styles.graphCol}>
              <SectionTitle>Attack chain graph</SectionTitle>
              <p style={styles.graphHint}>
                Traversed up to 5 hops from <strong>{selectedIP}</strong> through Neo4j.
                Click any node to inspect it.
              </p>
              <AttackGraph graphData={result.graph} />

              {/* Legend */}
              <div style={styles.legend}>
                {Object.entries(LEGEND_COLORS).map(([label, color]) => (
                  <span key={label} style={styles.legendItem}>
                    <span style={{ ...styles.legendDot, background: color }} />
                    {label}
                  </span>
                ))}
              </div>
            </div>

            {/* Right: node detail */}
            <div style={styles.detailCol}>
              <SectionTitle>Node detail</SectionTitle>
              <NodeDetail
                node={selectedNode}
                mongoDetail={result.mongoDetail}
                activeCampaigns={result.activeCampaigns}
              />
            </div>
          </div>
        </>
      )}

      {result && !result.found && (
        <div style={styles.notFound}>No graph data found for {selectedIP}</div>
      )}

      {status === "idle" && !result && (
        <div style={styles.emptyState}>
          <p style={styles.emptyText}>
            Select an IP address above and click <strong>Investigate</strong> to
            trace its full attack chain across Neo4j, MongoDB, and Redis.
          </p>
        </div>
      )}
    </div>
  );
};

// ── Small sub-components ─────────────────────────────────────────────────────
const SectionTitle = ({ children }) => (
  <h2 style={{ fontSize: 13, fontWeight: 600, color: "#5F5E5A",
    textTransform: "uppercase", letterSpacing: "0.08em", margin: "0 0 8px" }}>
    {children}
  </h2>
);

const Pill = ({ color, label }) => (
  <span style={{ background: color + "22", color, border: `1px solid ${color}55`,
    fontSize: 11, padding: "3px 10px", borderRadius: 20, fontWeight: 600,
    fontFamily: "monospace" }}>
    {label}
  </span>
);

const LEGEND_COLORS = {
  IP: "#185FA5", Domain: "#3B6D11", Malware: "#993C1D",
  CVE: "#854F0B", Exploit: "#A32D2D", Campaign: "#534AB7",
  ThreatActor: "#993556", Device: "#0F6E56",
};

// ── Styles ────────────────────────────────────────────────────────────────────
const styles = {
  page: { maxWidth: 1280, margin: "0 auto", padding: "24px 20px", fontFamily: "system-ui, sans-serif" },
  header: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24 },
  h1: { fontSize: 22, fontWeight: 700, color: "#2C2C2A", margin: "0 0 4px", display: "flex", alignItems: "center", gap: 8 },
  dot: { width: 10, height: 10, borderRadius: "50%", background: "#A32D2D", display: "inline-block" },
  sub: { fontSize: 13, color: "#888780", margin: 0 },
  dbPills: { display: "flex", gap: 6 },

  searchBar: {
    background: "#F9F8F5",
    border: "1px solid #D3D1C7",
    borderRadius: 10,
    padding: "16px 20px",
    marginBottom: 20,
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-end",
    gap: 16,
    flexWrap: "wrap",
  },
  searchInner: { flex: 1 },
  searchLabel: { display: "block", fontSize: 11, fontWeight: 600, color: "#5F5E5A",
    textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 },
  searchRow: { display: "flex", gap: 10, flexWrap: "wrap" },
  select: {
    padding: "9px 14px",
    fontSize: 14,
    border: "1px solid #B4B2A9",
    borderRadius: 6,
    background: "#fff",
    color: "#2C2C2A",
    minWidth: 220,
    cursor: "pointer",
  },
  btn: {
    padding: "9px 20px",
    fontSize: 14,
    fontWeight: 600,
    background: "#2E4057",
    color: "#fff",
    border: "none",
    borderRadius: 6,
    transition: "background 0.15s",
  },
  btnGhost: {
    padding: "9px 16px",
    fontSize: 13,
    background: "transparent",
    color: "#888780",
    border: "1px solid #D3D1C7",
    borderRadius: 6,
    cursor: "pointer",
  },
  ucBadge: {
    fontSize: 11,
    color: "#534AB7",
    background: "#EEEDFE",
    padding: "4px 12px",
    borderRadius: 20,
    fontWeight: 600,
    whiteSpace: "nowrap",
  },

  errorBox: {
    background: "#FCEBEB",
    color: "#791F1F",
    border: "1px solid #F09595",
    borderRadius: 8,
    padding: "12px 16px",
    fontSize: 13,
    marginBottom: 16,
  },

  resultGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 340px",
    gap: 20,
    alignItems: "start",
  },
  graphCol: {},
  detailCol: {
    background: "#FAFAF8",
    border: "1px solid #D3D1C7",
    borderRadius: 10,
    minHeight: 300,
    overflow: "hidden",
  },
  graphHint: { fontSize: 12, color: "#888780", margin: "0 0 10px" },

  legend: { display: "flex", flexWrap: "wrap", gap: 10, marginTop: 10 },
  legendItem: { display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "#5F5E5A" },
  legendDot: { width: 8, height: 8, borderRadius: "50%", flexShrink: 0 },

  notFound: {
    textAlign: "center",
    padding: 40,
    color: "#888780",
    fontSize: 14,
    background: "#F9F8F5",
    borderRadius: 10,
  },
  emptyState: {
    textAlign: "center",
    padding: "60px 40px",
    background: "#F9F8F5",
    borderRadius: 10,
    border: "2px dashed #D3D1C7",
  },
  emptyText: { color: "#888780", fontSize: 14, lineHeight: 1.6, maxWidth: 480, margin: "0 auto" },
};

export default InvestigationPage;
