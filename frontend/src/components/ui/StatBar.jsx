const StatBar = ({ stats, activeCampaigns }) => {
  if (!stats) return null;

  return (
    <div className="stat-bar">
      <Stat label="nodes" value={stats.totalNodes} color="#185FA5" />
      <Stat label="edges" value={stats.totalEdges} color="#3B6D11" />
      <Stat label="types" value={stats.nodeTypes?.join(" / ")} color="#534AB7" />
      {activeCampaigns?.length > 0 && (
        <Stat label="active campaigns" value={activeCampaigns.join(", ")} color="#A32D2D" />
      )}
    </div>
  );
};

const Stat = ({ label, value, color }) => (
  <div className="stat-card">
    <span className="stat-value" style={{ "--stat-color": color }}>
      {value}
    </span>
    <span className="stat-label">{label}</span>
  </div>
);

export default StatBar;
