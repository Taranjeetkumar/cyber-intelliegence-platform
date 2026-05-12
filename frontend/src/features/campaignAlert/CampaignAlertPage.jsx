import { useState, useEffect, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";

// ── Slice ─────────────────────────────────────────────────────────────────────
export const runCorrelation = createAsyncThunk("campaignAlert/correlate", async ({ topN = 20, threshold = 2 } = {}) => (await axios.post(`/api/campaigns/correlate?topN=${topN}&threshold=${threshold}`)).data);
export const fetchAlerts = createAsyncThunk("campaignAlert/alerts", async () => (await axios.get("/api/campaigns/alerts")).data);
export const fetchActiveCamps = createAsyncThunk("campaignAlert/active", async () => (await axios.get("/api/campaigns/active")).data);

const slice = createSlice({
    name: "campaignAlert",
    initialState: { alerts: [], liveAlerts: [], activeCampaigns: [], lastCorrelation: null, status: "idle" },
    reducers: {
        addLiveAlert: (s, a) => { s.liveAlerts = [a.payload, ...s.liveAlerts.slice(0, 19)]; },
    },
    extraReducers: (b) => {
        b.addCase(fetchAlerts.fulfilled, (s, a) => { s.alerts = a.payload; });
        b.addCase(fetchActiveCamps.fulfilled, (s, a) => { s.activeCampaigns = a.payload; });
        b.addCase(runCorrelation.pending, (s) => { s.status = "loading"; });
        b.addCase(runCorrelation.fulfilled, (s, a) => { s.lastCorrelation = a.payload; s.status = "succeeded"; });
        b.addCase(runCorrelation.rejected, (s) => { s.status = "failed"; });
    },
});

export const { addLiveAlert } = slice.actions;
export const selectAlerts = (s) => s.campaignAlert.alerts;
export const selectLiveAlerts = (s) => s.campaignAlert.liveAlerts;
export const selectActiveCampaigns = (s) => s.campaignAlert.activeCampaigns;
export const selectLastCorrelation = (s) => s.campaignAlert.lastCorrelation;
export const selectCAStatus = (s) => s.campaignAlert.status;
export default slice.reducer;

// ── Page ─────────────────────────────────────────────────────────────────────
const SEV_COLOR = { critical: "#A32D2D", high: "#854F0B", medium: "#534AB7", low: "#3B6D11" };
const SEV_BG = { critical: "#FCEBEB", high: "#FAEEDA", medium: "#EEEDFE", low: "#EAF3DE" };

export function CampaignAlertPage() {
    const dispatch = useDispatch();
    const alerts = useSelector(selectAlerts);
    const liveAlerts = useSelector(selectLiveAlerts);
    const activeCampaigns = useSelector(selectActiveCampaigns);
    const lastCorr = useSelector(selectLastCorrelation);
    const status = useSelector(selectCAStatus);
    const [threshold, setThreshold] = useState(2);
    const [sseStatus, setSseStatus] = useState("connecting");
    const esRef = useRef(null);

    useEffect(() => {
        dispatch(fetchAlerts());
        dispatch(fetchActiveCamps());

        // SSE — subscribe to Redis pub/sub via backend /api/alerts/stream
        const es = new EventSource("/api/alerts/stream");
        esRef.current = es;
        es.onopen = () => setSseStatus("connected");
        es.onerror = () => setSseStatus("disconnected");
        es.onmessage = (e) => {
            try { dispatch(addLiveAlert(JSON.parse(e.data))); } catch { }
        };
        return () => es.close();
    }, []);

    const handleCorrelate = () => {
        dispatch(runCorrelation({ topN: 20, threshold }))
            .then(() => { dispatch(fetchAlerts()); dispatch(fetchActiveCamps()); });
    };

    return (
        <div style={s.page}>
            <div style={s.header}>
                <div><h2 style={s.title}>UC6 — Campaign Pattern Detection</h2>
                    <p style={s.sub}>Redis ZREVRANGE + Neo4j COUNT(DISTINCT) + pub/sub SSE alerts</p></div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{
                        ...s.ssePill, background: sseStatus === "connected" ? "#EAF3DE" : "#FAEEDA",
                        color: sseStatus === "connected" ? "#27500A" : "#633806"
                    }}>
                        {sseStatus === "connected" ? "● Live" : "○ " + sseStatus}
                    </span>
                </div>
            </div>

            {/* Correlation trigger */}
            <div style={s.triggerBar}>
                <div style={s.triggerInfo}>
                    <strong>Correlation engine</strong> — reads top 20 IOCs from Redis, checks Neo4j for campaign membership,
                    fires alert if ≥ threshold IPs match the same campaign.
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "flex-end", flexShrink: 0 }}>
                    <div><label style={s.label}>Match threshold</label>
                        <input style={s.input} type="number" min="1" max="10" value={threshold}
                            onChange={e => setThreshold(Number(e.target.value))} /></div>
                    <button style={s.btn} onClick={handleCorrelate} disabled={status === "loading"}>
                        {status === "loading" ? "Running…" : "▶ Run Correlation"}</button>
                </div>
            </div>

            {/* Last correlation result */}
            {lastCorr && (
                <div style={s.corrResult}>
                    <div style={s.corrTitle}>Last correlation result</div>
                    <div style={s.corrMeta}>Checked {lastCorr.top_iocs_checked} IOCs · {lastCorr.matched_campaigns?.length} campaign(s) matched · {lastCorr.alerts?.length} new alert(s) fired</div>
                    {lastCorr.matched_campaigns?.map(c => (
                        <div key={c.campaign_id} style={s.campMatch}>
                            <span style={s.campName}>{c.campaign_name}</span>
                            <span style={s.campActor}>actor: {c.actor_name}</span>
                            <span style={s.campCount}>{c.matched_count} IPs matched</span>
                            <div style={s.matchedIps}>{c.matched_ips?.join(" · ")}</div>
                        </div>
                    ))}
                </div>
            )}

            <div style={s.grid}>
                {/* Live alert stream */}
                <div>
                    <div style={s.sectionTitle}>Live alert stream (SSE → Redis pub/sub)</div>
                    {liveAlerts.length === 0 && <p style={s.empty}>Run correlation to generate alerts. They appear here instantly via SSE.</p>}
                    {liveAlerts.map((a, i) => (
                        <div key={i} style={{ ...s.alertCard, borderColor: SEV_COLOR[a.severity] || "#D3D1C7", background: SEV_BG[a.severity] || "#FAFAF8" }}>
                            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
                                <span style={{ ...s.sevBadge, background: SEV_COLOR[a.severity], color: "#fff" }}>{a.severity || "alert"}</span>
                                <span style={s.alertTitle}>{a.campaign_name || a.type}</span>
                                <span style={s.alertTs}>{a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : ""}</span>
                            </div>
                            {a.actor_name && <div style={s.alertMeta}>Actor: {a.actor_name} · {a.matched_count} IOCs matched</div>}
                            {a.matched_ips && <div style={s.alertIps}>{a.matched_ips.join(" · ")}</div>}
                        </div>
                    ))}
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    {/* Active campaigns */}
                    <div style={s.card}>
                        <div style={s.cardTitle}>Active campaigns <span style={s.dbTag}>Redis SMEMBERS</span></div>
                        {activeCampaigns.length === 0 && <p style={s.empty}>None yet</p>}
                        {activeCampaigns.map(c => (
                            <div key={c} style={s.campRow}>
                                <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#A32D2D", display: "inline-block", marginRight: 6 }} />
                                <span style={{ fontSize: 12, fontFamily: "monospace" }}>{c}</span>
                            </div>
                        ))}
                    </div>

                    {/* Cypher used */}
                    <div style={{ ...s.card, background: "#1E1E2E" }}>
                        <div style={{ ...s.cardTitle, color: "#CDD6F4" }}>Neo4j query used</div>
                        <pre style={s.cypher}>{`MATCH (i:IP)
  -[:RESOLVES_TO|HOSTS*1..3]->
  (m:Malware)-[:USED_BY]->(c:Campaign)
WHERE i.value IN $ipList
WITH c,
  COUNT(DISTINCT i) AS matchCount
WHERE matchCount >= ${threshold}
MATCH (c)-[:OPERATED_BY]->(a:ThreatActor)
RETURN c.name, a.name, matchCount`}</pre>
                    </div>

                    {/* Persistent alerts */}
                    <div style={s.card}>
                        <div style={s.cardTitle}>Alert history <span style={s.dbTag}>MongoDB</span></div>
                        {alerts.slice(0, 5).map(a => (
                            <div key={a._id} style={{ padding: "6px 0", borderBottom: "1px solid #F1EFE8" }}>
                                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                                    <span style={{ ...s.sevBadge, background: SEV_COLOR[a.severity] || "#888", color: "#fff", fontSize: 9 }}>{a.severity}</span>
                                    <span style={{ fontSize: 12, color: "#2C2C2A" }}>{a.title}</span>
                                </div>
                                <div style={{ fontSize: 10, color: "#888780", marginTop: 2 }}>{new Date(a.createdAt).toLocaleString()}</div>
                            </div>
                        ))}
                        {alerts.length === 0 && <p style={s.empty}>No alerts yet</p>}
                    </div>
                </div>
            </div>
        </div>
    );
}

const s = {
    page: { padding: 20, fontFamily: "system-ui,sans-serif" },
    header: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 },
    title: { fontSize: 18, fontWeight: 700, color: "#2C2C2A", margin: 0 },
    sub: { fontSize: 12, color: "#888780", margin: "4px 0 0" },
    ssePill: { padding: "4px 10px", borderRadius: 20, fontSize: 11, fontWeight: 600 },
    triggerBar: { display: "flex", justifyContent: "space-between", alignItems: "flex-end", background: "#F9F8F5", border: "1px solid #D3D1C7", borderRadius: 10, padding: "14px 16px", marginBottom: 16, gap: 16, flexWrap: "wrap" },
    triggerInfo: { fontSize: 12, color: "#444441", lineHeight: 1.6, flex: 1 },
    label: { display: "block", fontSize: 11, fontWeight: 600, color: "#5F5E5A", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 4 },
    input: { padding: "7px 10px", fontSize: 13, border: "1px solid #B4B2A9", borderRadius: 6, width: 70 },
    btn: { padding: "8px 18px", background: "#A32D2D", color: "#fff", border: "none", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 600 },
    corrResult: { background: "#EEEDFE", border: "1px solid #9D99D8", borderRadius: 10, padding: 14, marginBottom: 16 },
    corrTitle: { fontSize: 12, fontWeight: 700, color: "#3C3489", marginBottom: 4 },
    corrMeta: { fontSize: 11, color: "#534AB7", marginBottom: 8 },
    campMatch: { background: "#fff", borderRadius: 6, padding: 8, marginBottom: 6, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" },
    campName: { fontSize: 12, fontWeight: 700, color: "#2C2C2A", fontFamily: "monospace" },
    campActor: { fontSize: 11, color: "#888780" },
    campCount: { fontSize: 11, fontWeight: 600, color: "#A32D2D", marginLeft: "auto" },
    matchedIps: { width: "100%", fontSize: 10, color: "#534AB7", fontFamily: "monospace" },
    grid: { display: "grid", gridTemplateColumns: "1fr 280px", gap: 16, alignItems: "start" },
    sectionTitle: { fontSize: 12, fontWeight: 700, color: "#5F5E5A", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 8 },
    empty: { fontSize: 12, color: "#888780", fontStyle: "italic", textAlign: "center", padding: "20px 0" },
    alertCard: { border: "2px solid", borderRadius: 8, padding: 12, marginBottom: 8 },
    sevBadge: { fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4, textTransform: "uppercase" },
    alertTitle: { fontSize: 13, fontWeight: 600, color: "#2C2C2A", flex: 1, fontFamily: "monospace" },
    alertTs: { fontSize: 10, color: "#888780" },
    alertMeta: { fontSize: 11, color: "#444441" },
    alertIps: { fontSize: 10, color: "#534AB7", fontFamily: "monospace", marginTop: 2 },
    card: { background: "#FAFAF8", border: "1px solid #D3D1C7", borderRadius: 10, padding: 14 },
    cardTitle: { fontSize: 11, fontWeight: 700, color: "#444441", marginBottom: 10, display: "flex", alignItems: "center", gap: 6 },
    dbTag: { fontSize: 9, background: "#EAF3DE", color: "#27500A", padding: "1px 6px", borderRadius: 3, fontFamily: "monospace", fontWeight: 400 },
    campRow: { padding: "5px 0", borderBottom: "1px solid #F1EFE8" },
    cypher: { fontSize: 10, color: "#A6E3A1", whiteSpace: "pre-wrap", lineHeight: 1.6 },
};
