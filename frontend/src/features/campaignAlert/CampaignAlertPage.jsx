import { useState, useEffect, useRef, useCallback } from "react";
import { useDispatch, useSelector } from "react-redux";
import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";
import { useTheme } from "../../context/ThemeContext";

// ── Async Thunks ─────────────────────────────────────────────────────────────────
export const runCorrelation = createAsyncThunk(
    "campaignAlert/correlate",
    async ({ topN = 20, threshold = 2 } = {}) => {
        const response = await axios.post(`/api/campaigns/correlate?topN=${topN}&threshold=${threshold}`);
        return response.data;
    }
);

export const fetchAlerts = createAsyncThunk(
    "campaignAlert/alerts",
    async (limit = 50) => {
        const response = await axios.get(`/api/campaigns/alerts?limit=${limit}`);
        return response.data;
    }
);

export const fetchActiveCamps = createAsyncThunk(
    "campaignAlert/active",
    async () => {
        const response = await axios.get("/api/campaigns/active");
        return response.data;
    }
);

export const fetchCorrelationStats = createAsyncThunk(
    "campaignAlert/stats",
    async () => {
        const response = await axios.get("/api/campaigns/stats");
        return response.data;
    }
);

export const clearActiveCampaigns = createAsyncThunk(
    "campaignAlert/clearActive",
    async () => {
        const response = await axios.delete("/api/campaigns/active");
        return response.data;
    }
);

// Live Threat Intel Thunks
export const fetchLiveThreatIntel = createAsyncThunk(
    "campaignAlert/fetchLive",
    async ({ source = "recent", limit = 20, query = "" } = {}) => {
        // Backend controller reads from req.query, so params must be sent as query string
        const params = new URLSearchParams({ source, limit });
        if (query) params.append("query", query);
        const response = await axios.post(`/api/threat-intel/fetch?${params.toString()}`);
        return response.data;
    }
);

export const fetchThreatIntelStatus = createAsyncThunk(
    "campaignAlert/intelStatus",
    async () => {
        const response = await axios.get("/api/threat-intel/status");
        return response.data;
    }
);

export const searchCampaigns = createAsyncThunk(
    "campaignAlert/searchCampaigns",
    async ({ keyword = "", severity = "", limit = 50 } = {}) => {
        const params = new URLSearchParams();
        if (keyword) params.append("keyword", keyword);
        if (severity) params.append("severity", severity);
        params.append("limit", limit);
        const response = await axios.get(`/api/threat-intel/campaigns?${params.toString()}`);
        return response.data;
    }
);

// ── Slice ─────────────────────────────────────────────────────────────────────
const slice = createSlice({
    name: "campaignAlert",
    initialState: {
        alerts: [],
        liveAlerts: [],
        activeCampaigns: [],
        lastCorrelation: null,
        correlationStats: null,
        threatIntelStatus: null,
        campaigns: [],
        status: "idle",
        fetchStatus: "idle",
        error: null
    },
    reducers: {
        addLiveAlert: (s, a) => {
            if (a.payload && a.payload.type !== "connected" && a.payload.type !== "error") {
                s.liveAlerts = [a.payload, ...s.liveAlerts.slice(0, 19)];
            }
        },
        clearError: (s) => { s.error = null; },
        clearLiveAlerts: (s) => { s.liveAlerts = []; },
    },
    extraReducers: (b) => {
        b.addCase(fetchAlerts.fulfilled, (s, a) => { s.alerts = a.payload; });
        b.addCase(fetchAlerts.rejected, (s, a) => { s.error = a.error?.message; });
        b.addCase(fetchActiveCamps.fulfilled, (s, a) => { s.activeCampaigns = a.payload; });
        b.addCase(fetchCorrelationStats.fulfilled, (s, a) => { s.correlationStats = a.payload; });
        b.addCase(runCorrelation.pending, (s) => { s.status = "loading"; s.error = null; });
        b.addCase(runCorrelation.fulfilled, (s, a) => { s.lastCorrelation = a.payload; s.status = "succeeded"; });
        b.addCase(runCorrelation.rejected, (s, a) => { s.status = "failed"; s.error = a.error?.message || "Correlation failed"; });
        b.addCase(clearActiveCampaigns.fulfilled, (s) => { s.activeCampaigns = []; });
        b.addCase(fetchLiveThreatIntel.pending, (s) => { s.fetchStatus = "loading"; s.error = null; });
        b.addCase(fetchLiveThreatIntel.fulfilled, (s, a) => {
            s.fetchStatus = "succeeded";
            // Merge fetch result stats into threatIntelStatus so UI fields (last_stats, last_fetch, etc.) stay correct
            if (a.payload?.stats) {
                s.threatIntelStatus = {
                    ...(s.threatIntelStatus || {}),
                    last_stats: a.payload.stats,
                    last_fetch: new Date().toISOString(),
                    total_campaigns: a.payload.stats.campaigns_stored ?? s.threatIntelStatus?.total_campaigns,
                    total_iocs: a.payload.stats.iocs_stored?.mongodb ?? s.threatIntelStatus?.total_iocs,
                    otx_configured: s.threatIntelStatus?.otx_configured,
                };
            }
        });
        b.addCase(fetchLiveThreatIntel.rejected, (s, a) => { s.fetchStatus = "failed"; s.error = a.error?.message || "Failed to fetch"; });
        b.addCase(fetchThreatIntelStatus.fulfilled, (s, a) => { s.threatIntelStatus = a.payload; });
        b.addCase(searchCampaigns.fulfilled, (s, a) => { s.campaigns = a.payload; });
    },
});

export const { addLiveAlert, clearError, clearLiveAlerts } = slice.actions;
export const selectAlerts = (s) => s.campaignAlert.alerts;
export const selectLiveAlerts = (s) => s.campaignAlert.liveAlerts;
export const selectActiveCampaigns = (s) => s.campaignAlert.activeCampaigns;
export const selectLastCorrelation = (s) => s.campaignAlert.lastCorrelation;
export const selectCorrelationStats = (s) => s.campaignAlert.correlationStats;
export const selectThreatIntelStatus = (s) => s.campaignAlert.threatIntelStatus;
export const selectCampaigns = (s) => s.campaignAlert.campaigns;
export const selectCAStatus = (s) => s.campaignAlert.status;
export const selectFetchStatus = (s) => s.campaignAlert.fetchStatus;
export const selectCAError = (s) => s.campaignAlert.error;
export default slice.reducer;

// ── Page Component ───────────────────────────────────────────────────────────
export function CampaignAlertPage() {
    const { theme, isDark } = useTheme();
    const dispatch = useDispatch();
    const alerts = useSelector(selectAlerts);
    const liveAlerts = useSelector(selectLiveAlerts);
    const activeCampaigns = useSelector(selectActiveCampaigns);
    const lastCorr = useSelector(selectLastCorrelation);
    const correlationStats = useSelector(selectCorrelationStats);
    const threatIntelStatus = useSelector(selectThreatIntelStatus);
    const campaigns = useSelector(selectCampaigns);
    const status = useSelector(selectCAStatus);
    const fetchStatus = useSelector(selectFetchStatus);
    const error = useSelector(selectCAError);

    const [threshold, setThreshold] = useState(2);
    const [fetchLimit, setFetchLimit] = useState(20);
    const [fetchSource, setFetchSource] = useState("recent");
    const [searchQuery, setSearchQuery] = useState("");
    const [sseStatus, setSseStatus] = useState("connecting");
    const [sseError, setSseError] = useState(null);
    const [activeTab, setActiveTab] = useState("overview");

    const esRef = useRef(null);
    const reconnectTimeoutRef = useRef(null);
    const reconnectAttempts = useRef(0);

    const SEV_COLOR = { critical: "#EF4444", high: "#F59E0B", medium: "#8B5CF6", low: "#22C55E" };
    const SEV_BG = isDark
        ? { critical: "#450A0A", high: "#422006", medium: "#2E1065", low: "#14532D" }
        : { critical: "#FEE2E2", high: "#FEF3C7", medium: "#EDE9FE", low: "#DCFCE7" };

    const connectSSE = useCallback(() => {
        if (esRef.current) { esRef.current.close(); esRef.current = null; }
        setSseStatus("connecting");
        setSseError(null);

        const es = new EventSource("/api/alerts/stream");
        esRef.current = es;

        es.onopen = () => { setSseStatus("connected"); setSseError(null); reconnectAttempts.current = 0; };
        es.onerror = () => {
            setSseStatus("disconnected");
            if (reconnectAttempts.current < 5) {
                const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
                setSseError(`Reconnecting in ${delay / 1000}s...`);
                reconnectTimeoutRef.current = setTimeout(() => { reconnectAttempts.current++; connectSSE(); }, delay);
            } else {
                setSseError("Connection failed. Please refresh.");
            }
        };
        es.onmessage = (e) => {
            try {
                const data = JSON.parse(e.data);
                if (data.type === "connected") setSseStatus("connected");
                else if (data.type === "error") setSseError(data.message);
                else {
                    dispatch(addLiveAlert(data));
                    dispatch(fetchAlerts());
                    dispatch(fetchActiveCamps());
                    dispatch(fetchCorrelationStats());
                }
            } catch (err) { console.error("SSE parse error", err); }
        };
        return es;
    }, [dispatch]);

    useEffect(() => {
        dispatch(fetchAlerts());
        dispatch(fetchActiveCamps());
        dispatch(fetchCorrelationStats());
        dispatch(fetchThreatIntelStatus());
        dispatch(searchCampaigns({ limit: 50 }));
        connectSSE();
        return () => {
            if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
            if (esRef.current) esRef.current.close();
        };
    }, [dispatch, connectSSE]);

    const handleCorrelate = () => {
        dispatch(runCorrelation({ topN: 20, threshold })).then(() => {
            dispatch(fetchAlerts());
            dispatch(fetchActiveCamps());
            dispatch(fetchCorrelationStats());
        });
    };

    const handleFetchLiveData = () => {
        dispatch(fetchLiveThreatIntel({ source: fetchSource, limit: fetchLimit, query: searchQuery })).then(() => {
            dispatch(fetchThreatIntelStatus());
            dispatch(fetchCorrelationStats());
            dispatch(searchCampaigns({ limit: 50 }));
        });
    };

    const handleClearActive = () => {
        dispatch(clearActiveCampaigns()).then(() => dispatch(fetchCorrelationStats()));
    };

    const s = {
        page: { padding: 24, fontFamily: "'Inter', system-ui, sans-serif", minHeight: "100%", background: theme.mainBg },
        header: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 },
        title: { fontSize: 22, fontWeight: 700, color: theme.textPrimary, margin: 0 },
        subtitle: { fontSize: 13, color: theme.textMuted, marginTop: 4 },
        ssePill: { padding: "6px 12px", borderRadius: 20, fontSize: 12, fontWeight: 600, display: "flex", alignItems: "center", gap: 6 },
        errorBanner: { background: theme.errorBg, border: `1px solid ${theme.error}`, borderRadius: 8, padding: "12px 16px", marginBottom: 16, display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 13, color: theme.error },
        tabs: { display: "flex", gap: 4, marginBottom: 20, background: theme.cardBg, padding: 4, borderRadius: 10, border: `1px solid ${theme.cardBorder}`, width: "fit-content" },
        tab: (active) => ({ padding: "10px 18px", borderRadius: 8, fontSize: 13, fontWeight: 600, cursor: "pointer", border: "none", background: active ? theme.accent : "transparent", color: active ? "#fff" : theme.textSecondary }),
        statsGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 14, marginBottom: 20 },
        statCard: { background: theme.cardBg, border: `1px solid ${theme.cardBorder}`, borderRadius: 10, padding: "16px 18px", boxShadow: theme.shadow },
        statLabel: { fontSize: 11, fontWeight: 600, color: theme.textMuted, textTransform: "uppercase", letterSpacing: ".08em", marginBottom: 6 },
        statValue: { fontSize: 24, fontWeight: 700, color: theme.textPrimary },
        triggerBar: { display: "flex", justifyContent: "space-between", alignItems: "flex-end", background: theme.cardBg, border: `1px solid ${theme.cardBorder}`, borderRadius: 12, padding: "18px 20px", marginBottom: 20, gap: 20, flexWrap: "wrap", boxShadow: theme.shadow },
        label: { display: "block", fontSize: 11, fontWeight: 600, color: theme.textMuted, textTransform: "uppercase", letterSpacing: ".08em", marginBottom: 6 },
        input: { padding: "10px 12px", fontSize: 14, border: `1px solid ${theme.inputBorder}`, borderRadius: 8, width: 80, background: theme.inputBg, color: theme.textPrimary, outline: "none" },
        select: { padding: "10px 12px", fontSize: 14, border: `1px solid ${theme.inputBorder}`, borderRadius: 8, background: theme.inputBg, color: theme.textPrimary, cursor: "pointer" },
        btn: { padding: "10px 20px", background: theme.accent, color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", fontSize: 14, fontWeight: 600 },
        btnSuccess: { padding: "10px 20px", background: isDark ? "#166534" : "#22C55E", color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", fontSize: 14, fontWeight: 600 },
        btnDanger: { padding: "8px 14px", background: theme.errorBg, color: theme.error, border: `1px solid ${theme.error}`, borderRadius: 6, cursor: "pointer", fontSize: 12, fontWeight: 500 },
        card: { background: theme.cardBg, border: `1px solid ${theme.cardBorder}`, borderRadius: 12, padding: 16, boxShadow: theme.shadow },
        cardTitle: { fontSize: 12, fontWeight: 700, color: theme.textSecondary, marginBottom: 12, display: "flex", alignItems: "center", gap: 8 },
        dbTag: { fontSize: 10, background: theme.successBg, color: theme.success, padding: "2px 8px", borderRadius: 4, fontFamily: "monospace", fontWeight: 500 },
        empty: { fontSize: 13, color: theme.textMuted, fontStyle: "italic", textAlign: "center", padding: "30px 0" },
        grid: { display: "grid", gridTemplateColumns: "1fr 320px", gap: 20, alignItems: "start" },
        corrResult: { background: isDark ? "#1E3A5F" : "#EFF6FF", border: `1px solid ${isDark ? "#3B82F6" : "#93C5FD"}`, borderRadius: 12, padding: 18, marginBottom: 20 },
        corrTitle: { fontSize: 13, fontWeight: 700, color: theme.info, marginBottom: 6 },
        corrMeta: { fontSize: 12, color: isDark ? "#93C5FD" : "#3B82F6", marginBottom: 10 },
        corrMessage: { fontSize: 12, color: theme.textMuted, fontStyle: "italic", marginBottom: 10, padding: "8px 12px", background: theme.cardBg, borderRadius: 6 },
        campMatch: { background: theme.cardBg, borderRadius: 8, padding: 12, marginBottom: 8, display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", border: `1px solid ${theme.cardBorder}` },
        alertCard: { borderRadius: 10, padding: 14, marginBottom: 10 },
        sevBadge: { fontSize: 10, fontWeight: 700, padding: "3px 8px", borderRadius: 4, textTransform: "uppercase" },
        campRow: { padding: "8px 0", borderBottom: `1px solid ${theme.cardBorder}` },
        workflowSteps: { display: "flex", alignItems: "center", gap: 12, marginBottom: 20, padding: "16px 20px", background: theme.cardBg, borderRadius: 12, border: `1px solid ${theme.cardBorder}`, flexWrap: "wrap" },
        workflowStep: (active, done) => ({ display: "flex", alignItems: "center", gap: 8, padding: "8px 14px", borderRadius: 8, fontSize: 12, fontWeight: 600, background: done ? theme.successBg : active ? theme.infoBg : theme.cardBg, color: done ? theme.success : active ? theme.info : theme.textMuted, border: `1px solid ${done ? theme.success : active ? theme.info : theme.cardBorder}` }),
    };

    const hasIOCs = (correlationStats?.hot_iocs_count || 0) > 0;
    const hasCampaigns = (threatIntelStatus?.total_campaigns || campaigns?.length || 0) > 0;
    const hasMatches = lastCorr?.matched_campaigns?.length > 0;

    return (
        <div style={s.page}>
            <div style={s.header}>
                <div>
                    <h2 style={s.title}>Campaign Pattern Detection</h2>
                    <p style={s.subtitle}>Fetch live threat intelligence, correlate IOCs, and detect campaign patterns</p>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ ...s.ssePill, background: sseStatus === "connected" ? theme.successBg : sseStatus === "connecting" ? theme.warningBg : theme.errorBg, color: sseStatus === "connected" ? theme.success : sseStatus === "connecting" ? theme.warning : theme.error }}>
                        <span style={{ width: 8, height: 8, borderRadius: "50%", background: sseStatus === "connected" ? theme.success : sseStatus === "connecting" ? theme.warning : theme.error, animation: sseStatus === "connected" ? "pulse 2s infinite" : "none" }} />
                        {sseStatus === "connected" ? "Live" : sseStatus === "connecting" ? "Connecting..." : "Disconnected"}
                    </span>
                    {sseStatus === "disconnected" && <button style={{ ...s.btn, padding: "6px 12px", fontSize: 12 }} onClick={() => { reconnectAttempts.current = 0; connectSSE(); }}>Reconnect</button>}
                </div>
            </div>

            {sseError && <div style={s.errorBanner}><span>{sseError}</span></div>}
            {error && <div style={s.errorBanner}><span>Error: {error}</span><button style={s.btnDanger} onClick={() => dispatch(clearError())}>Dismiss</button></div>}

            {/* Workflow Steps */}
            <div style={s.workflowSteps}>
                <div style={s.workflowStep(fetchStatus === "loading", hasIOCs)}><span>{hasIOCs ? "✓" : "1"}</span><span>Fetch Live Data</span></div>
                <span style={{ fontSize: 18, color: theme.textMuted }}>→</span>
                <div style={s.workflowStep(false, hasCampaigns)}><span>{hasCampaigns ? "✓" : "2"}</span><span>Store Campaigns</span></div>
                <span style={{ fontSize: 18, color: theme.textMuted }}>→</span>
                <div style={s.workflowStep(status === "loading", hasMatches)}><span>{hasMatches ? "✓" : "3"}</span><span>Run Correlation</span></div>
                <span style={{ fontSize: 18, color: theme.textMuted }}>→</span>
                <div style={s.workflowStep(false, alerts.length > 0)}><span>{alerts.length > 0 ? "✓" : "4"}</span><span>Generate Alerts</span></div>
            </div>

            {/* Tabs */}
            <div style={s.tabs}>
                {["overview", "fetch", "correlate", "campaigns", "alerts"].map(t => (
                    <button key={t} style={s.tab(activeTab === t)} onClick={() => setActiveTab(t)}>{t.charAt(0).toUpperCase() + t.slice(1)}</button>
                ))}
            </div>

            {/* Stats Grid */}
            <div style={s.statsGrid}>
                <div style={s.statCard}><div style={s.statLabel}>Hot IOCs (Redis)</div><div style={s.statValue}>{correlationStats?.hot_iocs_count || 0}</div></div>
                <div style={s.statCard}><div style={s.statLabel}>Campaigns (DB)</div><div style={s.statValue}>{correlationStats?.campaigns_in_db || threatIntelStatus?.total_campaigns || 0}</div></div>
                <div style={s.statCard}><div style={s.statLabel}>Total IOCs</div><div style={s.statValue}>{threatIntelStatus?.total_iocs || 0}</div></div>
                <div style={s.statCard}><div style={s.statLabel}>Active Campaigns</div><div style={{ ...s.statValue, color: activeCampaigns.length > 0 ? theme.error : theme.textPrimary }}>{activeCampaigns.length}</div></div>
                <div style={s.statCard}><div style={s.statLabel}>Total Alerts</div><div style={s.statValue}>{correlationStats?.total_alerts || alerts.length}</div></div>
                <div style={s.statCard}><div style={s.statLabel}>OTX API</div><div style={{ ...s.statValue, fontSize: 14, color: threatIntelStatus?.otx_configured ? theme.success : theme.warning }}>{threatIntelStatus?.otx_configured ? "Configured" : "Not Set"}</div></div>
            </div>

            {/* Overview Tab */}
            {activeTab === "overview" && (
                <div style={s.grid}>
                    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                        <div style={s.card}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                                <div style={s.cardTitle}>Live Alert Stream<span style={{ ...s.dbTag, background: theme.errorBg, color: theme.error }}>SSE</span></div>
                                {liveAlerts.length > 0 && <button style={s.btnDanger} onClick={() => dispatch(clearLiveAlerts())}>Clear</button>}
                            </div>
                            {liveAlerts.length === 0 && <p style={s.empty}>Run correlation to generate alerts. They appear here instantly via SSE.</p>}
                            {liveAlerts.slice(0, 5).map((a, i) => (
                                <div key={i} style={{ ...s.alertCard, border: `2px solid ${SEV_COLOR[a.severity] || theme.cardBorder}`, background: SEV_BG[a.severity] || theme.cardBg }}>
                                    <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 6 }}>
                                        <span style={{ ...s.sevBadge, background: SEV_COLOR[a.severity], color: "#fff" }}>{a.severity || "alert"}</span>
                                        <span style={{ fontSize: 14, fontWeight: 600, color: theme.textPrimary, flex: 1, fontFamily: "monospace" }}>{a.campaign_name || a.type}</span>
                                        <span style={{ fontSize: 11, color: theme.textMuted }}>{a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : ""}</span>
                                    </div>
                                    {a.actor_name && <div style={{ fontSize: 12, color: theme.textSecondary }}>Actor: {a.actor_name} · {a.matched_count} IOCs matched</div>}
                                    {a.matched_ips && <div style={{ fontSize: 11, color: theme.info, fontFamily: "monospace", marginTop: 4 }}>{a.matched_ips.slice(0, 5).join(" · ")}{a.matched_ips.length > 5 ? ` (+${a.matched_ips.length - 5})` : ""}</div>}
                                </div>
                            ))}
                        </div>
                        {lastCorr && (
                            <div style={s.corrResult}>
                                <div style={s.corrTitle}>Last Correlation Result</div>
                                <div style={s.corrMeta}>Checked {lastCorr.top_iocs_checked || 0} IOCs | {lastCorr.matched_campaigns?.length || 0} campaign(s) | {lastCorr.alerts?.length || 0} new alert(s)</div>
                                {lastCorr.message && <div style={s.corrMessage}>{lastCorr.message}</div>}
                                {lastCorr.matched_campaigns?.slice(0, 3).map(c => (
                                    <div key={c.campaign_id} style={s.campMatch}>
                                        <span style={{ fontSize: 13, fontWeight: 700, color: theme.textPrimary, fontFamily: "monospace" }}>{c.campaign_name}</span>
                                        <span style={{ fontSize: 12, color: theme.textMuted }}>Actor: {c.actor_name || "Unknown"}</span>
                                        <span style={{ fontSize: 12, fontWeight: 600, color: theme.error, marginLeft: "auto" }}>{c.matched_count} IOCs</span>
                                        <div style={{ width: "100%", fontSize: 11, color: theme.info, fontFamily: "monospace" }}>{c.matched_ips?.slice(0, 5).join(" · ")}</div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                        <div style={s.card}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                                <div style={s.cardTitle}>Active Campaigns<span style={s.dbTag}>Redis</span></div>
                                {activeCampaigns.length > 0 && <button style={s.btnDanger} onClick={handleClearActive}>Clear</button>}
                            </div>
                            {activeCampaigns.length === 0 && <p style={s.empty}>None yet</p>}
                            {activeCampaigns.map(c => (
                                <div key={c} style={s.campRow}>
                                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                        <span style={{ width: 8, height: 8, borderRadius: "50%", background: theme.error, boxShadow: `0 0 6px ${theme.error}80` }} />
                                        <span style={{ fontSize: 12, fontFamily: "monospace", color: theme.textPrimary }}>{c}</span>
                                    </div>
                                </div>
                            ))}
                        </div>
                        <div style={s.card}>
                            <div style={s.cardTitle}>Alert History<span style={{ ...s.dbTag, background: theme.infoBg, color: theme.info }}>MongoDB</span></div>
                            {alerts.slice(0, 5).map(a => (
                                <div key={a._id} style={{ padding: "10px 0", borderBottom: `1px solid ${theme.cardBorder}` }}>
                                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                                        <span style={{ ...s.sevBadge, background: SEV_COLOR[a.severity] || theme.textMuted, color: "#fff", fontSize: 9 }}>{a.severity}</span>
                                        <span style={{ fontSize: 12, color: theme.textPrimary }}>{a.title}</span>
                                    </div>
                                    <div style={{ fontSize: 11, color: theme.textMuted, marginTop: 4 }}>{new Date(a.createdAt).toLocaleString()}</div>
                                </div>
                            ))}
                            {alerts.length === 0 && <p style={s.empty}>No alerts yet</p>}
                        </div>
                    </div>
                </div>
            )}

            {/* Fetch Tab */}
            {activeTab === "fetch" && (
                <div>
                    <div style={s.triggerBar}>
                        <div style={{ fontSize: 13, color: theme.textSecondary, lineHeight: 1.7, flex: 1 }}>
                            <strong style={{ color: theme.textPrimary }}>Live Threat Intelligence Fetcher</strong> — Fetches real-time threat data from AlienVault OTX and stores to MongoDB, Redis, Neo4j.
                            {!threatIntelStatus?.otx_configured && <div style={{ marginTop: 8, padding: "8px 12px", background: theme.warningBg, borderRadius: 6, color: theme.warning }}>OTX_API_KEY not set. Using public API with rate limits.</div>}
                        </div>
                        <div style={{ display: "flex", gap: 12, alignItems: "flex-end", flexWrap: "wrap" }}>
                            <div><label style={s.label}>Source</label><select style={s.select} value={fetchSource} onChange={e => setFetchSource(e.target.value)}><option value="recent">Recent</option><option value="subscribed">Subscribed</option><option value="search">Search</option></select></div>
                            {fetchSource === "search" && <div><label style={s.label}>Query</label><input style={{ ...s.input, width: 150 }} type="text" placeholder="e.g., APT29" value={searchQuery} onChange={e => setSearchQuery(e.target.value)} /></div>}
                            <div><label style={s.label}>Limit</label><input style={s.input} type="number" min="5" max="100" value={fetchLimit} onChange={e => setFetchLimit(Number(e.target.value))} /></div>
                            <button style={{ ...s.btnSuccess, opacity: fetchStatus === "loading" ? 0.7 : 1 }} onClick={handleFetchLiveData} disabled={fetchStatus === "loading"}>{fetchStatus === "loading" ? "Fetching..." : "Fetch Live Data"}</button>
                        </div>
                    </div>
                    {threatIntelStatus?.last_stats && (
                        <div style={s.corrResult}>
                            <div style={s.corrTitle}>Last Fetch Result</div>
                            <div style={s.corrMeta}>Fetched {threatIntelStatus.last_stats.pulses_fetched || 0} pulses | {threatIntelStatus.last_stats.campaigns_stored || 0} campaigns | {threatIntelStatus.last_stats.iocs_stored?.mongodb || 0} IOCs (MongoDB) | {threatIntelStatus.last_stats.iocs_stored?.redis || 0} IOCs (Redis)</div>
                            <div style={s.corrMessage}>Last fetch: {threatIntelStatus.last_fetch ? new Date(threatIntelStatus.last_fetch).toLocaleString() : "Never"}</div>
                        </div>
                    )}
                </div>
            )}

            {/* Correlate Tab */}
            {activeTab === "correlate" && (
                <div>
                    <div style={s.triggerBar}>
                        <div style={{ fontSize: 13, color: theme.textSecondary, lineHeight: 1.7, flex: 1 }}>
                            <strong style={{ color: theme.textPrimary }}>Correlation Engine</strong> — Reads top IOCs from Redis, checks Neo4j/MongoDB for campaign membership, fires alerts if matches meet threshold.
                        </div>
                        <div style={{ display: "flex", gap: 12, alignItems: "flex-end" }}>
                            <div><label style={s.label}>Threshold</label><input style={s.input} type="number" min="1" max="10" value={threshold} onChange={e => setThreshold(Number(e.target.value))} /></div>
                            <button style={{ ...s.btn, opacity: status === "loading" ? 0.7 : 1 }} onClick={handleCorrelate} disabled={status === "loading"}>{status === "loading" ? "Running..." : "Run Correlation"}</button>
                        </div>
                    </div>
                    {correlationStats?.hot_iocs_count === 0 && <div style={{ ...s.corrMessage, background: theme.warningBg, color: theme.warning, padding: 16, borderRadius: 8, marginBottom: 20 }}>No IOCs in Redis. Fetch live data first.</div>}
                    {lastCorr && (
                        <div style={s.corrResult}>
                            <div style={s.corrTitle}>Correlation Result</div>
                            <div style={s.corrMeta}>Checked {lastCorr.top_iocs_checked || 0} IOCs | {lastCorr.matched_campaigns?.length || 0} campaign(s) | {lastCorr.alerts?.length || 0} new alert(s)</div>
                            {lastCorr.message && <div style={s.corrMessage}>{lastCorr.message}</div>}
                            {lastCorr.matched_campaigns?.map(c => (
                                <div key={c.campaign_id || c.campaign_name} style={s.campMatch}>
                                    <span style={{ fontSize: 13, fontWeight: 700, color: theme.textPrimary, fontFamily: "monospace" }}>{c.campaign_name}</span>
                                    <span style={{ fontSize: 12, color: theme.textMuted }}>Actor: {c.actor_name || "Unknown"}</span>
                                    <span style={{ ...s.sevBadge, background: SEV_COLOR[c.severity] || SEV_COLOR.medium, color: "#fff" }}>{c.severity || "medium"}</span>
                                    <span style={{ fontSize: 12, fontWeight: 600, color: theme.error, marginLeft: "auto" }}>{c.matched_count} IOCs</span>
                                    <div style={{ width: "100%", fontSize: 11, color: theme.info, fontFamily: "monospace" }}>{c.matched_ips?.join(" · ") || c.matched_iocs?.join(" · ")}</div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* Campaigns Tab */}
            {activeTab === "campaigns" && (
                <div style={s.card}>
                    <div style={{ ...s.cardTitle, marginBottom: 16 }}>Stored Campaigns<span style={{ ...s.dbTag, background: theme.infoBg, color: theme.info }}>MongoDB</span><span style={{ marginLeft: "auto", fontSize: 12, color: theme.textMuted }}>{campaigns.length} campaigns</span></div>
                    <div style={{ maxHeight: 500, overflowY: "auto" }}>
                        {campaigns.length === 0 && <p style={s.empty}>No campaigns. Fetch live data first.</p>}
                        {campaigns.map(c => (
                            <div key={c._id || c.campaign_id} style={{ padding: "12px 14px", borderBottom: `1px solid ${theme.cardBorder}` }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                                    <span style={{ ...s.sevBadge, background: SEV_COLOR[c.severity] || SEV_COLOR.low, color: "#fff" }}>{c.severity || "low"}</span>
                                    <span style={{ fontSize: 13, fontWeight: 600, color: theme.textPrimary }}>{c.name}</span>
                                </div>
                                <div style={{ fontSize: 11, color: theme.textMuted, display: "flex", gap: 12, flexWrap: "wrap" }}>
                                    {c.threat_actor && <span>Actor: {c.threat_actor}</span>}
                                    <span>Source: {c.source || "unknown"}</span>
                                    <span>Modified: {c.last_modified ? new Date(c.last_modified).toLocaleDateString() : "N/A"}</span>
                                </div>
                                <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                                    {c.iocs?.ips?.length > 0 && <span style={{ fontSize: 10, background: theme.infoBg, color: theme.info, padding: "2px 8px", borderRadius: 4 }}>{c.iocs.ips.length} IPs</span>}
                                    {c.iocs?.domains?.length > 0 && <span style={{ fontSize: 10, background: theme.infoBg, color: theme.info, padding: "2px 8px", borderRadius: 4 }}>{c.iocs.domains.length} Domains</span>}
                                    {c.iocs?.hashes?.length > 0 && <span style={{ fontSize: 10, background: theme.infoBg, color: theme.info, padding: "2px 8px", borderRadius: 4 }}>{c.iocs.hashes.length} Hashes</span>}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Alerts Tab */}
            {activeTab === "alerts" && (
                <div style={s.card}>
                    <div style={{ ...s.cardTitle, marginBottom: 16 }}>All Alerts<span style={{ ...s.dbTag, background: theme.infoBg, color: theme.info }}>MongoDB</span><span style={{ marginLeft: "auto", fontSize: 12, color: theme.textMuted }}>{alerts.length} alerts</span></div>
                    {alerts.length === 0 && <p style={s.empty}>No alerts. Run correlation after fetching data.</p>}
                    {alerts.map(a => (
                        <div key={a._id} style={{ ...s.alertCard, border: `1px solid ${SEV_COLOR[a.severity] || theme.cardBorder}`, background: SEV_BG[a.severity] || theme.cardBg }}>
                            <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 6 }}>
                                <span style={{ ...s.sevBadge, background: SEV_COLOR[a.severity] || theme.textMuted, color: "#fff" }}>{a.severity}</span>
                                <span style={{ fontSize: 14, fontWeight: 600, color: theme.textPrimary, flex: 1, fontFamily: "monospace" }}>{a.title}</span>
                                <span style={{ fontSize: 11, color: theme.textMuted }}>{new Date(a.createdAt).toLocaleString()}</span>
                            </div>
                            {a.description && <div style={{ fontSize: 12, color: theme.textSecondary }}>{a.description}</div>}
                            {a.meta?.matched_ips && <div style={{ fontSize: 11, color: theme.info, fontFamily: "monospace", marginTop: 4 }}>{a.meta.matched_ips.slice(0, 10).join(" · ")}{a.meta.matched_ips.length > 10 ? ` (+${a.meta.matched_ips.length - 10})` : ""}</div>}
                        </div>
                    ))}
                </div>
            )}

            <style>{`@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }`}</style>
        </div>
    );
}