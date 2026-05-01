const GROUP_BADGE_COLORS = {
  IP: "#185FA5",
  Domain: "#3B6D11",
  Malware: "#993C1D",
  CVE: "#854F0B",
  Exploit: "#A32D2D",
  Campaign: "#534AB7",
  ThreatActor: "#993556",
  Device: "#0F6E56",
  Port: "#5F5E5A",
  Service: "#888780",
};

const NodeDetail = ({ node, mongoDetail, abuseIpDb, otx, activeCampaigns }) => {
  if (!node) {
    return (
      <div className="detail-empty">
        <p className="detail-hint">Click any node in the graph to see details</p>
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
    <div className="detail-panel">
      <div className="detail-header">
        <span className="node-badge" style={{ background: badgeColor }}>
          {node.group}
        </span>
        <h3 className="detail-title">{node.label}</h3>
        {activeCampaigns?.includes(props.campaign_id || props.name) && (
          <span className="active-pill">ACTIVE</span>
        )}
      </div>

      <div className="detail-section">
        <p className="detail-section-title">Graph properties</p>
        {Object.entries(props).map(([k, v]) => (
          <DetailRow key={k} label={k.replace(/_/g, " ")} value={String(v)} />
        ))}
      </div>

      {mongoDetail && node.group === "IP" && (
        <div className="detail-section">
          <p className="detail-section-title">MongoDB enrichment</p>
          {mongoDetail.tags?.length > 0 && (
            <DetailRow label="tags" value={mongoDetail.tags.join(", ")} />
          )}
          <DetailRow label="confidence" value={mongoDetail.confidence ?? "-"} />
          {mongoDetail.enrichment &&
            Object.entries(mongoDetail.enrichment).map(([k, v]) => (
              <DetailRow key={k} label={k.replace(/_/g, " ")} value={String(v)} />
            ))}

          {mongoDetail.analyst_notes && (
            <div>
              <p className="detail-key">analyst notes</p>
              <p className="detail-notes">{mongoDetail.analyst_notes}</p>
            </div>
          )}
        </div>
      )}

      {node.group === "IP" && (
        <div className="detail-section">
          <p className="detail-section-title">AbuseIPDB reputation</p>
          {!abuseIpDb?.configured && (
            <p className="detail-notes">Set ABUSEIPDB_API_KEY in backend/.env to enable live reputation checks.</p>
          )}
          {abuseIpDb?.error && abuseIpDb.configured && (
            <p className="detail-notes">{abuseIpDb.error}</p>
          )}
          {abuseData && (
            <>
              <DetailRow label="abuse score" value={abuseData.abuseConfidenceScore ?? "n/a"} />
              <DetailRow label="total reports" value={abuseData.totalReports ?? "n/a"} />
              <DetailRow label="country" value={abuseData.countryCode || "n/a"} />
              <DetailRow label="isp" value={abuseData.isp || "n/a"} />
              <DetailRow label="usage" value={abuseData.usageType || "n/a"} />
              <DetailRow label="last reported" value={abuseData.lastReportedAt || "n/a"} />
            </>
          )}
        </div>
      )}

      {node.group === "IP" && (
        <div className="detail-section">
          <p className="detail-section-title">AlienVault OTX</p>
          {otx?.errors?.length > 0 && <p className="detail-notes">{otx.errors.join("; ")}</p>}
          {!otx?.configured && (
            <p className="detail-notes">
              Public OTX indicator data is enabled. Set OTX_API_KEY in backend/.env for authenticated access.
            </p>
          )}
          {otxGeneral && (
            <>
              <DetailRow label="pulse count" value={otxPulseInfo?.count ?? 0} />
              <DetailRow label="reputation" value={otxReputation?.reputation ?? otxGeneral.reputation ?? "n/a"} />
              <DetailRow label="country" value={otxGeneral.country_name || otxGeneral.country_code || "n/a"} />
              <DetailRow label="asn" value={otxGeneral.asn || "n/a"} />
              <DetailRow label="sections" value={otxGeneral.sections?.join(", ") || "n/a"} />
              {otxPulses.length > 0 && (
                <div>
                  <p className="detail-key">latest pulses</p>
                  {otxPulses.slice(0, 3).map((pulse) => (
                    <p key={pulse.id || pulse.name} className="detail-notes">
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

const DetailRow = ({ label, value }) => (
  <div className="detail-row">
    <span className="detail-key">{label}</span>
    <span className="detail-value">{value}</span>
  </div>
);

export default NodeDetail;
