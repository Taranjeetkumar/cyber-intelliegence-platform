import { useEffect, useState } from "react";
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
} from "./investigationSlice";
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
  const selectedIPValue = selectedIP.trim();
  const [themeMode, setThemeMode] = useState(() => {
    const saved = window.localStorage.getItem("soc-theme");
    if (saved === "day" || saved === "night") return saved;
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "night" : "day";
  });

  useEffect(() => {
    dispatch(fetchKnownIPs());
  }, [dispatch]);

  useEffect(() => {
    window.localStorage.setItem("soc-theme", themeMode);
  }, [themeMode]);

  const handleInvestigate = () => {
    if (selectedIPValue) dispatch(investigateIP(selectedIPValue));
  };

  const handleClear = () => dispatch(clearResult());
  const toggleTheme = () => setThemeMode((mode) => (mode === "night" ? "day" : "night"));

  return (
    <div className="soc-shell" data-theme={themeMode}>
      <main className="soc-layout">
        <header className="soc-header">
          <div>
            <p className="eyebrow">Security operations control</p>
            <h1 className="soc-title">
              <span className="status-light" />
              CTI Command Center
            </h1>
            <p className="soc-subtitle">
              Cyber threat intelligence / attack chain investigation / live malicious signal triage
            </p>
          </div>
          <div className="header-actions">
            <button className="theme-toggle" type="button" onClick={toggleTheme}>
              {themeMode === "night" ? "Day mode" : "Night mode"}
            </button>
            <div className="pill-row">
              <Pill color="var(--accent)" label="MongoDB" />
              <Pill color="var(--success)" label="Redis" />
              <Pill color="var(--danger)" label="Neo4j" />
            </div>
          </div>
        </header>

        <div className="search-panel">
          <div className="search-inner">
            <label className="field-label">Select or enter suspicious IP</label>
            <div className="search-row">
              <select
                className="soc-select"
                value={knownIPs.includes(selectedIP) ? selectedIP : ""}
                onChange={(e) => dispatch(setSelectedIP(e.target.value))}
              >
                <option value="">Choose an IP</option>
                {knownIPs.map((ip) => (
                  <option key={ip} value={ip}>
                    {ip}
                  </option>
                ))}
              </select>
              <input
                className="soc-input"
                value={selectedIP}
                onChange={(e) => dispatch(setSelectedIP(e.target.value))}
                placeholder="or type a public IP"
              />
              <button
                className="primary-btn"
                onClick={handleInvestigate}
                disabled={status === "loading" || !selectedIPValue}
              >
                {status === "loading" ? "Investigating..." : "Investigate"}
              </button>
              {result && (
                <button className="ghost-btn" onClick={handleClear}>
                  Clear
                </button>
              )}
            </div>
          </div>

          <div className="uc-badge">UC1 / Neo4j graph traversal</div>
        </div>

        {error && (
          <div className="error-box">
            <strong>Error:</strong> {error}
          </div>
        )}

        {result && result.found && (
          <>
            <StatBar stats={result.stats} activeCampaigns={result.activeCampaigns} />

            <div className="result-grid">
              <div>
                <div className="graph-heading">
                  <SectionTitle>Attack chain graph</SectionTitle>
                  <p className="graph-hint">
                    {result.threatOnly ? "Live reputation lookup for" : "Traversed up to 5 hops from"}{" "}
                    <strong>{selectedIPValue}</strong>
                    {result.threatOnly ? "." : " through Neo4j."} Click any node to inspect it.
                  </p>
                </div>
                <AttackGraph graphData={result.graph} themeMode={themeMode} />

                <div className="legend">
                  {Object.entries(LEGEND_COLORS).map(([label, color]) => (
                    <span key={label} className="legend-item">
                      <span className="legend-dot" style={{ background: color }} />
                      {label}
                    </span>
                  ))}
                </div>
              </div>

              <div className="detail-shell">
                <SectionTitle>Node detail</SectionTitle>
                <NodeDetail
                  node={selectedNode}
                  mongoDetail={result.mongoDetail}
                  abuseIpDb={result.abuseIpDb}
                  otx={result.otx}
                  activeCampaigns={result.activeCampaigns}
                />
              </div>
            </div>
          </>
        )}

        {result && !result.found && (
          <div className="not-found">No graph data found for {selectedIPValue}</div>
        )}

        {status === "idle" && !result && (
          <div className="empty-state">
            <p className="empty-text">
              Select an IP address above and click <strong>Investigate</strong> to trace its full attack
              chain across Neo4j, MongoDB, and Redis.
            </p>
          </div>
        )}
      </main>
    </div>
  );
};

const SectionTitle = ({ children }) => <h2 className="section-title">{children}</h2>;

const Pill = ({ color, label }) => (
  <span className="source-pill" style={{ color, background: `color-mix(in srgb, ${color} 12%, transparent)` }}>
    {label}
  </span>
);

const LEGEND_COLORS = {
  IP: "#185FA5",
  Domain: "#3B6D11",
  Malware: "#993C1D",
  CVE: "#854F0B",
  Exploit: "#A32D2D",
  Campaign: "#534AB7",
  ThreatActor: "#993556",
  Device: "#0F6E56",
};

export default InvestigationPage;
