// Shows full properties of a clicked graph node

const GROUP_BADGE_COLORS = {
  IP:          "#185FA5",
  Domain:      "#3B6D11",
  Malware:     "#993C1D",
  CVE:         "#854F0B",
  Exploit:     "#A32D2D",
  Campaign:    "#534AB7",
  ThreatActor: "#993556",
  Device:      "#0F6E56",
  Port:        "#5F5E5A",
  Service:     "#888780",
};

const NodeDetail = ({ node, mongoDetail, abuseIpDb, otx, activeCampaigns }) => {
  if (!node) {
    return (
      <div style={styles.empty}>
        <p style={styles.hint}>Click any node in the graph to see details</p>
      </div>
    );
  }

  const badgeColor = GROUP_BADGE_COLORS[node.group] || "#888";
  const props = node.properties || {};
  const abuseData = abuseIpDb?.data;
  const otxGeneral = otx?.general;
  const otxReputation = otx?.reputation;
  const otxPulseInfo = otxGeneral?.pulse_info;
  const otxPulses = otxPulseInfo?.pulses || [];

  return (
    <div style={styles.panel}>
      {/* Header */}
      <div style={styles.header}>
        <span style={{ ...styles.badge, background: badgeColor }}>
          {node.group}
        </span>
        <h3 style={styles.title}>{node.label}</h3>
        {activeCampaigns?.includes(props.campaign_id || props.name) && (
          <span style={styles.activePill}>🔴 ACTIVE</span>
        )}
      </div>

      {/* Node properties from Neo4j */}
      <div style={styles.section}>
        <p style={styles.sectionTitle}>Graph properties</p>
        {Object.entries(props).map(([k, v]) => (
          <div key={k} style={styles.row}>
            <span style={styles.key}>{k.replace(/_/g, " ")}</span>
            <span style={styles.val}>{String(v)}</span>
          </div>
        ))}
      </div>

      {/* MongoDB enrichment (only for IP nodes) */}
      {mongoDetail && node.group === "IP" && (
        <div style={styles.section}>
          <p style={styles.sectionTitle}>MongoDB enrichment</p>
          {mongoDetail.tags?.length > 0 && (
            <div style={styles.row}>
              <span style={styles.key}>tags</span>
              <span style={styles.val}>{mongoDetail.tags.join(", ")}</span>
            </div>
          )}
          <div style={styles.row}>
            <span style={styles.key}>confidence</span>
            <span style={styles.val}>{mongoDetail.confidence ?? "—"}</span>
          </div>
          {mongoDetail.enrichment && Object.entries(mongoDetail.enrichment).map(([k, v]) => (
            <div key={k} style={styles.row}>
              <span style={styles.key}>{k.replace(/_/g, " ")}</span>
              <span style={styles.val}>{String(v)}</span>
            </div>
          ))}
          
          {mongoDetail.analyst_notes && (
            <div style={{ marginTop: 8 }}>
              <p style={styles.key}>analyst notes</p>
              <p style={styles.notes}>{mongoDetail.analyst_notes}</p>
            </div>
          )}
        </div>
      )}

      {node.group === "IP" && (
        <div style={styles.section}>
          <p style={styles.sectionTitle}>AbuseIPDB reputation</p>
          {!abuseIpDb?.configured && (
            <p style={styles.notes}>Set ABUSEIPDB_API_KEY in backend/.env to enable live reputation checks.</p>
          )}
          {abuseIpDb?.error && abuseIpDb.configured && (
            <p style={styles.notes}>{abuseIpDb.error}</p>
          )}
          {abuseData && (
            <>
              <div style={styles.row}>
                <span style={styles.key}>abuse score</span>
                <span style={styles.val}>{abuseData.abuseConfidenceScore ?? "n/a"}</span>
              </div>
              <div style={styles.row}>
                <span style={styles.key}>total reports</span>
                <span style={styles.val}>{abuseData.totalReports ?? "n/a"}</span>
              </div>
              <div style={styles.row}>
                <span style={styles.key}>country</span>
                <span style={styles.val}>{abuseData.countryCode || "n/a"}</span>
              </div>
              <div style={styles.row}>
                <span style={styles.key}>isp</span>
                <span style={styles.val}>{abuseData.isp || "n/a"}</span>
              </div>
              <div style={styles.row}>
                <span style={styles.key}>usage</span>
                <span style={styles.val}>{abuseData.usageType || "n/a"}</span>
              </div>
              <div style={styles.row}>
                <span style={styles.key}>last reported</span>
                <span style={styles.val}>{abuseData.lastReportedAt || "n/a"}</span>
              </div>
            </>
          )}
        </div>
      )}

      {node.group === "IP" && (
        <div style={styles.section}>
          <p style={styles.sectionTitle}>AlienVault OTX</p>
          {otx?.errors?.length > 0 && (
            <p style={styles.notes}>{otx.errors.join("; ")}</p>
          )}
          {!otx?.configured && (
            <p style={styles.notes}>
              Public OTX indicator data is enabled. Set OTX_API_KEY in backend/.env for authenticated access.
            </p>
          )}
          {otxGeneral && (
            <>
              <div style={styles.row}>
                <span style={styles.key}>pulse count</span>
                <span style={styles.val}>{otxPulseInfo?.count ?? 0}</span>
              </div>
              <div style={styles.row}>
                <span style={styles.key}>reputation</span>
                <span style={styles.val}>{otxReputation?.reputation ?? otxGeneral.reputation ?? "n/a"}</span>
              </div>
              <div style={styles.row}>
                <span style={styles.key}>country</span>
                <span style={styles.val}>{otxGeneral.country_name || otxGeneral.country_code || "n/a"}</span>
              </div>
              <div style={styles.row}>
                <span style={styles.key}>asn</span>
                <span style={styles.val}>{otxGeneral.asn || "n/a"}</span>
              </div>
              <div style={styles.row}>
                <span style={styles.key}>sections</span>
                <span style={styles.val}>{otxGeneral.sections?.join(", ") || "n/a"}</span>
              </div>
              {otxPulses.length > 0 && (
                <div style={{ marginTop: 8 }}>
                  <p style={styles.key}>latest pulses</p>
                  {otxPulses.slice(0, 3).map((pulse) => (
                    <p key={pulse.id || pulse.name} style={styles.notes}>
                      {pulse.name || pulse.id}
                    </p>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};

const styles = {
  empty: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    height: "100%",
    minHeight: 200,
  },
  hint: { color: "#888780", fontSize: 13, fontStyle: "italic" },
  panel: { padding: "16px", fontFamily: "monospace" },
  header: { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 16 },
  badge: {
    color: "#fff",
    fontSize: 11,
    fontWeight: 600,
    padding: "2px 8px",
    borderRadius: 4,
    textTransform: "uppercase",
    letterSpacing: "0.04em",
  },
  title: { margin: 0, fontSize: 15, fontWeight: 600, color: "#2C2C2A", flex: 1 },
  activePill: {
    background: "#FCEBEB",
    color: "#A32D2D",
    fontSize: 11,
    padding: "2px 8px",
    borderRadius: 4,
    fontWeight: 600,
  },
  section: {
    marginBottom: 16,
    borderTop: "1px solid #E8E6DF",
    paddingTop: 12,
  },
  sectionTitle: {
    fontSize: 11,
    textTransform: "uppercase",
    letterSpacing: "0.08em",
    color: "#888780",
    margin: "0 0 8px",
    fontWeight: 600,
  },
  row: {
    display: "flex",
    justifyContent: "space-between",
    gap: 8,
    padding: "3px 0",
    borderBottom: "1px solid #F1EFE8",
    fontSize: 12,
  },
  key: { color: "#5F5E5A", minWidth: 120, flexShrink: 0, textTransform: "lowercase" },
  val: { color: "#2C2C2A", wordBreak: "break-all", textAlign: "right" },
  notes: {
    fontSize: 12,
    color: "#444441",
    lineHeight: 1.5,
    background: "#F9F8F5",
    padding: 8,
    borderRadius: 4,
    marginTop: 4,
  },
};

export default NodeDetail;
