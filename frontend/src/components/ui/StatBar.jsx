const StatBar = ({ stats, activeCampaigns }) => {
  if (!stats) return null;

  return (
    <div style={styles.bar}>
      <Stat label="nodes" value={stats.totalNodes} color="#185FA5" />
      <Stat label="edges" value={stats.totalEdges} color="#3B6D11" />
      <Stat label="types" value={stats.nodeTypes?.join(" · ")} color="#534AB7" wide />
      {activeCampaigns?.length > 0 && (
        <Stat label="active campaigns" value={activeCampaigns.join(", ")} color="#A32D2D" wide />
      )}
    </div>
  );
};

const Stat = ({ label, value, color, wide }) => (
  <div style={{ ...styles.stat, flex: wide ? 2 : 1 }}>
    <span style={{ ...styles.val, color }}>{value}</span>
    <span style={styles.label}>{label}</span>
  </div>
);

const styles = {
  bar: {
    display: "flex",
    gap: 1,
    background: "#F1EFE8",
    borderRadius: 8,
    overflow: "hidden",
    marginBottom: 16,
  },
  stat: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    padding: "10px 12px",
    background: "#FAFAF8",
    borderRight: "1px solid #E8E6DF",
  },
  val: { fontSize: 16, fontWeight: 700, fontFamily: "monospace", marginBottom: 2 },
  label: { fontSize: 10, color: "#888780", textTransform: "uppercase", letterSpacing: "0.06em" },
};

export default StatBar;
