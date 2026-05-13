import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
    fetchLeaderboard, fetchDeviceScores, fetchActiveCampaigns,
    selectLeaderboard, selectDeviceScores, selectActiveCampaigns, selectUpdatedAt
} from "./iocMonitorSlice";

const SEVERITY_COLOR = (score) =>
    score >= 80 ? "#A32D2D" : score >= 60 ? "#854F0B" : "#3B6D11";

export default function IocMonitorPage() {
    const dispatch = useDispatch();
    const leaderboard = useSelector(selectLeaderboard);
    const deviceScores = useSelector(selectDeviceScores);
    const activeCampaigns = useSelector(selectActiveCampaigns);
    const updatedAt = useSelector(selectUpdatedAt);

    const refresh = () => {
        dispatch(fetchLeaderboard());
        dispatch(fetchDeviceScores());
        dispatch(fetchActiveCampaigns());
    };

    // Auto-refresh every 10 seconds (simulates real-time)
    useEffect(() => {
        refresh();
        const id = setInterval(refresh, 10000);
        return () => clearInterval(id);
    }, []);

    const maxHits = leaderboard[0]?.hits || 1;

    return (
        <div style={s.page}>
            <div style={s.header}>
                <div>
                    <h2 style={s.title}>Live IOC Monitor</h2>
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    {updatedAt && <span style={s.ts}>Updated: {new Date(updatedAt).toLocaleTimeString()}</span>}
                    <button style={s.btn} onClick={refresh}>↺ Refresh</button>
                </div>
            </div>

            <div style={s.grid}>
                {/* Leaderboard */}
                <div style={s.card}>
                    <div style={s.cardTitle}>🔥 Hot IOC Leaderboard <span style={s.dbTag}>Redis ZREVRANGE</span></div>
                    {leaderboard.length === 0 && <p style={s.empty}>No data yet</p>}
                    {leaderboard.map((item) => (
                        <div key={item.value} style={s.iocRow}>
                            <span style={s.rank}>#{item.rank}</span>
                            <div style={{ flex: 1 }}>
                                <div style={s.iocVal}>{item.value}</div>
                                <div style={s.iocMeta}>
                                    {item.tags?.join(", ")} · confidence {item.confidence ?? "—"}
                                    {item.enrichment?.whois_country && ` · ${item.enrichment.whois_country}`}
                                </div>
                                <div style={s.barWrap}>
                                    <div style={{ ...s.bar, width: `${(item.hits / maxHits) * 100}%`, background: SEVERITY_COLOR(item.hits * 2) }} />
                                </div>
                            </div>
                            <span style={s.hits}>{item.hits}</span>
                        </div>
                    ))}
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                    {/* Device risk scores */}
                    <div style={s.card}>
                        <div style={s.cardTitle}>⚠ Device Risk Scores <span style={s.dbTag}>Redis TTL keys</span></div>
                        {deviceScores.length === 0 && <p style={s.empty}>No risk scores cached</p>}
                        {deviceScores.map((d) => (
                            <div key={d.hostname} style={s.deviceRow}>
                                <div>
                                    <div style={s.hostname}>{d.hostname}</div>
                                    <div style={s.ttl}>expires in {d.ttl_seconds}s</div>
                                </div>
                                <div style={{ ...s.score, color: SEVERITY_COLOR(d.risk_score) }}>
                                    {d.risk_score}
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Active campaigns */}
                    <div style={s.card}>
                        <div style={s.cardTitle}>🎯 Active Campaigns <span style={s.dbTag}>Redis SMEMBERS</span></div>
                        {activeCampaigns.length === 0 && <p style={s.empty}>No active campaigns</p>}
                        {activeCampaigns.map((c) => (
                            <div key={c} style={s.campRow}>
                                <span style={s.campDot} />
                                <span style={s.campName}>{c}</span>
                            </div>
                        ))}
                    </div>

                </div>
            </div>
        </div>
    );
}

const s = {
    page: { padding: "20px", fontFamily: "system-ui,sans-serif" },
    header: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 },
    title: { fontSize: 18, fontWeight: 700, color: "#2C2C2A", margin: 0 },
    sub: { fontSize: 12, color: "#888780", margin: "4px 0 0" },
    ts: { fontSize: 11, color: "#888780" },
    btn: { padding: "7px 14px", background: "#3B6D11", color: "#fff", border: "none", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 600 },
    grid: { display: "grid", gridTemplateColumns: "1fr 340px", gap: 16 },
    card: { background: "#FAFAF8", border: "1px solid #D3D1C7", borderRadius: 10, padding: 16 },
    cardTitle: { fontSize: 12, fontWeight: 700, color: "#444441", marginBottom: 12, display: "flex", alignItems: "center", gap: 8 },
    dbTag: { fontSize: 10, background: "#EAF3DE", color: "#27500A", padding: "2px 7px", borderRadius: 4, fontFamily: "monospace", fontWeight: 400 },
    empty: { fontSize: 12, color: "#888780", fontStyle: "italic", textAlign: "center", padding: "20px 0" },
    iocRow: { display: "flex", alignItems: "center", gap: 8, padding: "8px 0", borderBottom: "1px solid #F1EFE8" },
    rank: { fontSize: 11, color: "#888780", width: 24, flexShrink: 0, textAlign: "right" },
    iocVal: { fontSize: 13, fontWeight: 600, color: "#2C2C2A", fontFamily: "monospace" },
    iocMeta: { fontSize: 11, color: "#888780", margin: "2px 0 4px" },
    barWrap: { height: 4, background: "#F1EFE8", borderRadius: 2, overflow: "hidden" },
    bar: { height: "100%", borderRadius: 2, transition: "width 0.5s" },
    hits: { fontSize: 16, fontWeight: 700, color: "#2E4057", width: 36, textAlign: "right", flexShrink: 0 },
    deviceRow: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: "1px solid #F1EFE8" },
    hostname: { fontSize: 13, fontWeight: 600, color: "#2C2C2A", fontFamily: "monospace" },
    ttl: { fontSize: 10, color: "#888780" },
    score: { fontSize: 22, fontWeight: 700, fontFamily: "monospace" },
    campRow: { display: "flex", alignItems: "center", gap: 8, padding: "6px 0" },
    campDot: { width: 8, height: 8, borderRadius: "50%", background: "#A32D2D", flexShrink: 0 },
    campName: { fontSize: 13, fontFamily: "monospace", color: "#2C2C2A" },
};
