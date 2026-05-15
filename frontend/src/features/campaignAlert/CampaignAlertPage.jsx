import { useState, useEffect, useRef, useCallback } from "react";
import { useDispatch, useSelector } from "react-redux";
import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";
import { useTheme } from "../../context/ThemeContext";

// ── Slice ─────────────────────────────────────────────────────────────────────
export const runCorrelation = createAsyncThunk("campaignAlert/correlate", async ({ topN = 20, threshold = 2 } = {}) => (await axios.post(`/api/campaigns/correlate?topN=${topN}&threshold=${threshold}`)).data);
export const importLiveFeed = createAsyncThunk("campaignAlert/liveFeed", async ({ limit = 5, confidenceMinimum = 90 } = {}) => (await axios.post(`/api/campaigns/live-feed?limit=${limit}&confidenceMinimum=${confidenceMinimum}`)).data);
export const fetchAlerts = createAsyncThunk("campaignAlert/alerts", async () => (await axios.get("/api/campaigns/alerts")).data);
export const fetchActiveCamps = createAsyncThunk("campaignAlert/active", async () => (await axios.get("/api/campaigns/active")).data);

const slice = createSlice({
    name: "campaignAlert",
    initialState: {
        alerts: [],
        liveAlerts: [],
        activeCampaigns: [],
        lastCorrelation: null,
        lastLiveFeed: null,
        status: "idle",
        error: null
    },
    reducers: {
        addLiveAlert: (s, a) => {
            if (a.payload && a.payload.type !== "connected" && a.payload.type !== "error") {
                s.liveAlerts = [a.payload, ...s.liveAlerts.slice(0, 19)];
            }
        },
        clearError: (s) => { s.error = null; },
    },
    extraReducers: (b) => {
        b.addCase(fetchAlerts.fulfilled, (s, a) => { s.alerts = a.payload; });
        b.addCase(fetchActiveCamps.fulfilled, (s, a) => { s.activeCampaigns = a.payload; });
        b.addCase(runCorrelation.pending, (s) => { s.status = "loading"; s.error = null; });
        b.addCase(runCorrelation.fulfilled, (s, a) => {
            s.lastCorrelation = a.payload;
            s.status = "succeeded";
        });
        b.addCase(runCorrelation.rejected, (s, a) => {
            s.status = "failed";
            s.error = a.error?.message || "Correlation failed";
        });
        b.addCase(importLiveFeed.pending, (s) => { s.status = "loading"; s.error = null; });
        b.addCase(importLiveFeed.fulfilled, (s, a) => {
            s.lastLiveFeed = a.payload;
            s.status = "succeeded";
        });
        b.addCase(importLiveFeed.rejected, (s, a) => {
            s.status = "failed";
            s.error = a.error?.message || "Live feed import failed";
        });
    },
});

export const { addLiveAlert, clearError } = slice.actions;
export const selectAlerts = (s) => s.campaignAlert.alerts;
export const selectLiveAlerts = (s) => s.campaignAlert.liveAlerts;
export const selectActiveCampaigns = (s) => s.campaignAlert.activeCampaigns;
export const selectLastCorrelation = (s) => s.campaignAlert.lastCorrelation;
export const selectLastLiveFeed = (s) => s.campaignAlert.lastLiveFeed;
export const selectCAStatus = (s) => s.campaignAlert.status;
export const selectCAError = (s) => s.campaignAlert.error;
export default slice.reducer;

// ── Page ─────────────────────────────────────────────────────────────────────
export function CampaignAlertPage() {
    const { theme, isDark } = useTheme();
    const dispatch = useDispatch();
    const alerts = useSelector(selectAlerts);
    const liveAlerts = useSelector(selectLiveAlerts);
    const activeCampaigns = useSelector(selectActiveCampaigns);
    const lastCorr = useSelector(selectLastCorrelation);
    const lastLiveFeed = useSelector(selectLastLiveFeed);
    const status = useSelector(selectCAStatus);
    const error = useSelector(selectCAError);
    const [threshold, setThreshold] = useState(2);
    const [sseStatus, setSseStatus] = useState("connecting");
    const [sseError, setSseError] = useState(null);
    const esRef = useRef(null);
    const reconnectTimeoutRef = useRef(null);
    const reconnectAttempts = useRef(0);
    const maxReconnectAttempts = 5;

    // Severity colors
    const SEV_COLOR = {
        critical: "#EF4444",
        high: "#F59E0B",
        medium: "#8B5CF6",
        low: "#22C55E"
    };
    const SEV_BG = isDark ? {
        critical: "#450A0A",
        high: "#422006",
        medium: "#2E1065",
        low: "#14532D"
    } : {
        critical: "#FEE2E2",
        high: "#FEF3C7",
        medium: "#EDE9FE",
        low: "#DCFCE7"
    };

    // SSE connection with reconnection logic
    const connectSSE = useCallback(() => {
        if (esRef.current) {
            esRef.current.close();
            esRef.current = null;
        }

        setSseStatus("connecting");
        setSseError(null);

        const es = new EventSource("/api/alerts/stream");
        esRef.current = es;

        es.onopen = () => {
            setSseStatus("connected");
            setSseError(null);
            reconnectAttempts.current = 0;
        };

        es.onerror = () => {
            setSseStatus("disconnected");
            if (reconnectAttempts.current < maxReconnectAttempts) {
                const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
                setSseError(`Connection lost. Reconnecting in ${delay/1000}s...`);
                reconnectTimeoutRef.current = setTimeout(() => {
                    reconnectAttempts.current++;
                    connectSSE();
                }, delay);
            } else {
                setSseError("Connection failed. Please refresh the page.");
            }
        };

        es.onmessage = (e) => {
            try {
                const data = JSON.parse(e.data);
                if (data.type === "connected") {
                    setSseStatus("connected");
                } else if (data.type === "error") {
                    setSseError(data.message);
                } else {
                    dispatch(addLiveAlert(data));
                    dispatch(fetchAlerts());
                    dispatch(fetchActiveCamps());
                }
            } catch (parseError) {
                console.error("SSE: Failed to parse message", e.data, parseError);
            }
        };

        return es;
    }, [dispatch]);

    useEffect(() => {
        dispatch(fetchAlerts());
        dispatch(fetchActiveCamps());
        connectSSE();

        return () => {
            if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
            if (esRef.current) esRef.current.close();
        };
    }, [dispatch, connectSSE]);

    const handleCorrelate = () => {
        dispatch(runCorrelation({ topN: 20, threshold }))
            .then(() => {
                dispatch(fetchAlerts());
                dispatch(fetchActiveCamps());
            });
    };

    const handleImportLiveFeed = () => {
        dispatch(importLiveFeed({ limit: 5, confidenceMinimum: 90 }))
            .then(() => dispatch(runCorrelation({ topN: 20, threshold: 1 })))
            .then(() => {
                dispatch(fetchAlerts());
                dispatch(fetchActiveCamps());
            });
    };

    const handleReconnect = () => {
        reconnectAttempts.current = 0;
        connectSSE();
    };

    // Dynamic styles based on theme
    const s = {
        page: {
            padding: 24,
            fontFamily: "'Inter', system-ui, sans-serif",
            minHeight: "100%",
            background: theme.mainBg,
        },
        header: {
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            marginBottom: 20
        },
        title: {
            fontSize: 22,
            fontWeight: 700,
            color: theme.textPrimary,
            margin: 0,
            letterSpacing: "-0.02em",
        },
        ssePill: {
            padding: "6px 12px",
            borderRadius: 20,
            fontSize: 12,
            fontWeight: 600,
            display: "flex",
            alignItems: "center",
            gap: 6,
        },
        reconnectBtn: {
            padding: "6px 12px",
            background: theme.accent,
            color: "#fff",
            border: "none",
            borderRadius: 6,
            fontSize: 12,
            cursor: "pointer",
            fontWeight: 500,
            transition: "all 0.2s ease",
        },
        errorBanner: {
            background: theme.errorBg,
            border: `1px solid ${theme.error}`,
            borderRadius: 8,
            padding: "12px 16px",
            marginBottom: 16,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            fontSize: 13,
            color: theme.error,
        },
        dismissBtn: {
            background: "transparent",
            border: `1px solid ${theme.error}`,
            color: theme.error,
            padding: "4px 10px",
            borderRadius: 4,
            fontSize: 11,
            cursor: "pointer",
            fontWeight: 500,
        },
        triggerBar: {
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-end",
            background: theme.cardBg,
            border: `1px solid ${theme.cardBorder}`,
            borderRadius: 12,
            padding: "18px 20px",
            marginBottom: 20,
            gap: 20,
            flexWrap: "wrap",
            boxShadow: theme.shadow,
        },
        triggerInfo: {
            fontSize: 13,
            color: theme.textSecondary,
            lineHeight: 1.7,
            flex: 1
        },
        label: {
            display: "block",
            fontSize: 11,
            fontWeight: 600,
            color: theme.textMuted,
            textTransform: "uppercase",
            letterSpacing: ".08em",
            marginBottom: 6
        },
        input: {
            padding: "10px 12px",
            fontSize: 14,
            border: `1px solid ${theme.inputBorder}`,
            borderRadius: 8,
            width: 80,
            background: theme.inputBg,
            color: theme.textPrimary,
            outline: "none",
            transition: "all 0.2s ease",
        },
        btn: {
            padding: "10px 20px",
            background: theme.accent,
            color: "#fff",
            border: "none",
            borderRadius: 8,
            cursor: "pointer",
            fontSize: 14,
            fontWeight: 600,
            transition: "all 0.2s ease",
            boxShadow: `0 2px 8px ${theme.accent}40`,
        },
        corrResult: {
            background: isDark ? "#1E3A5F" : "#EFF6FF",
            border: `1px solid ${isDark ? "#3B82F6" : "#93C5FD"}`,
            borderRadius: 12,
            padding: 18,
            marginBottom: 20
        },
        corrTitle: {
            fontSize: 13,
            fontWeight: 700,
            color: theme.info,
            marginBottom: 6
        },
        corrMeta: {
            fontSize: 12,
            color: isDark ? "#93C5FD" : "#3B82F6",
            marginBottom: 10
        },
        corrMessage: {
            fontSize: 12,
            color: theme.textMuted,
            fontStyle: "italic",
            marginBottom: 10,
            padding: "8px 12px",
            background: theme.cardBg,
            borderRadius: 6
        },
        campMatch: {
            background: theme.cardBg,
            borderRadius: 8,
            padding: 12,
            marginBottom: 8,
            display: "flex",
            gap: 10,
            flexWrap: "wrap",
            alignItems: "center",
            border: `1px solid ${theme.cardBorder}`,
        },
        campName: {
            fontSize: 13,
            fontWeight: 700,
            color: theme.textPrimary,
            fontFamily: "monospace"
        },
        campActor: {
            fontSize: 12,
            color: theme.textMuted
        },
        campCount: {
            fontSize: 12,
            fontWeight: 600,
            color: theme.error,
            marginLeft: "auto"
        },
        matchedIps: {
            width: "100%",
            fontSize: 11,
            color: theme.info,
            fontFamily: "monospace"
        },
        grid: {
            display: "grid",
            gridTemplateColumns: "1fr 300px",
            gap: 20,
            alignItems: "start"
        },
        sectionTitle: {
            fontSize: 11,
            fontWeight: 700,
            color: theme.textMuted,
            textTransform: "uppercase",
            letterSpacing: ".1em",
            marginBottom: 12
        },
        empty: {
            fontSize: 13,
            color: theme.textMuted,
            fontStyle: "italic",
            textAlign: "center",
            padding: "30px 0"
        },
        alertCard: {
            borderRadius: 10,
            padding: 14,
            marginBottom: 10,
            transition: "all 0.2s ease",
        },
        sevBadge: {
            fontSize: 10,
            fontWeight: 700,
            padding: "3px 8px",
            borderRadius: 4,
            textTransform: "uppercase",
            letterSpacing: ".04em",
        },
        alertTitle: {
            fontSize: 14,
            fontWeight: 600,
            color: theme.textPrimary,
            flex: 1,
            fontFamily: "monospace"
        },
        alertTs: {
            fontSize: 11,
            color: theme.textMuted
        },
        alertMeta: {
            fontSize: 12,
            color: theme.textSecondary
        },
        alertIps: {
            fontSize: 11,
            color: theme.info,
            fontFamily: "monospace",
            marginTop: 4
        },
        card: {
            background: theme.cardBg,
            border: `1px solid ${theme.cardBorder}`,
            borderRadius: 12,
            padding: 16,
            boxShadow: theme.shadow,
        },
        cardTitle: {
            fontSize: 12,
            fontWeight: 700,
            color: theme.textSecondary,
            marginBottom: 12,
            display: "flex",
            alignItems: "center",
            gap: 8
        },
        dbTag: {
            fontSize: 10,
            background: theme.successBg,
            color: theme.success,
            padding: "2px 8px",
            borderRadius: 4,
            fontFamily: "monospace",
            fontWeight: 500
        },
        campRow: {
            padding: "8px 0",
            borderBottom: `1px solid ${theme.cardBorder}`
        },
    };

    return (
        <div style={s.page}>
            <div style={s.header}>
                <div>
                    <h2 style={s.title}>Campaign Pattern Detection</h2>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{
                        ...s.ssePill,
                        background: sseStatus === "connected" ? theme.successBg : sseStatus === "connecting" ? theme.warningBg : theme.errorBg,
                        color: sseStatus === "connected" ? theme.success : sseStatus === "connecting" ? theme.warning : theme.error
                    }}>
                        <span style={{
                            width: 8,
                            height: 8,
                            borderRadius: "50%",
                            background: sseStatus === "connected" ? theme.success : sseStatus === "connecting" ? theme.warning : theme.error,
                            animation: sseStatus === "connected" ? "pulse 2s infinite" : "none",
                        }} />
                        {sseStatus === "connected" ? "Live" : sseStatus === "connecting" ? "Connecting..." : "Disconnected"}
                    </span>
                    {sseStatus === "disconnected" && (
                        <button style={s.reconnectBtn} onClick={handleReconnect}>Reconnect</button>
                    )}
                </div>
            </div>

            {sseError && (
                <div style={s.errorBanner}>
                    <span>{sseError}</span>
                </div>
            )}

            {error && (
                <div style={s.errorBanner}>
                    <span>Error: {error}</span>
                    <button style={s.dismissBtn} onClick={() => dispatch(clearError())}>Dismiss</button>
                </div>
            )}

            <div style={s.triggerBar}>
                <div style={s.triggerInfo}>
                    <strong style={{ color: theme.textPrimary }}>Correlation Engine</strong> — Reads top 20 IOCs from Redis,
                    checks Neo4j campaign membership, enriches with AbuseIPDB + AlienVault OTX, and fires alerts for matched live intel.
                </div>
                <div style={{ display: "flex", gap: 12, alignItems: "flex-end", flexShrink: 0 }}>
                    <div>
                        <label style={s.label}>Threshold</label>
                        <input
                            style={s.input}
                            type="number"
                            min="1"
                            max="10"
                            value={threshold}
                            onChange={e => setThreshold(Number(e.target.value))}
                        />
                    </div>
                    <button
                        style={{
                            ...s.btn,
                            background: "#2563EB",
                            boxShadow: "0 2px 8px #2563EB40",
                            opacity: status === "loading" ? 0.7 : 1,
                            cursor: status === "loading" ? "not-allowed" : "pointer",
                        }}
                        onClick={handleImportLiveFeed}
                        disabled={status === "loading"}
                    >
                        {status === "loading" ? "Loading..." : "Load Live Feeds"}
                    </button>
                    <button
                        style={{
                            ...s.btn,
                            opacity: status === "loading" ? 0.7 : 1,
                            cursor: status === "loading" ? "not-allowed" : "pointer",
                        }}
                        onClick={handleCorrelate}
                        disabled={status === "loading"}
                    >
                        {status === "loading" ? "Running..." : "Run Correlation"}
                    </button>
                </div>
            </div>

            {lastLiveFeed && (
                <div style={s.corrResult}>
                    <div style={s.corrTitle}>Live Feed Import</div>
                    <div style={s.corrMeta}>
                        {lastLiveFeed.count || 0} AbuseIPDB/OTX IP(s) added to Redis hot:iocs
                    </div>
                    {lastLiveFeed.message && (
                        <div style={s.corrMessage}>{lastLiveFeed.message}</div>
                    )}
                    {lastLiveFeed.imported?.map((item) => (
                        <div key={item.value} style={s.campMatch}>
                            <span style={s.campName}>{item.value}</span>
                            <span style={s.campActor}>Source: {item.source}</span>
                            {item.abuse_score !== undefined && <span style={s.campActor}>AbuseIPDB: {item.abuse_score}</span>}
                            {item.total_reports !== undefined && <span style={s.campActor}>Reports: {item.total_reports}</span>}
                            {item.pulse_name && <span style={s.campActor}>Pulse: {item.pulse_name}</span>}
                            {item.adversary && <span style={s.campActor}>Adversary: {item.adversary}</span>}
                            {item.country && <span style={s.campActor}>Country: {item.country}</span>}
                        </div>
                    ))}
                </div>
            )}

            {lastCorr && (
                <div style={s.corrResult}>
                    <div style={s.corrTitle}>Last Correlation Result</div>
                    <div style={s.corrMeta}>
                        Checked {lastCorr.top_iocs_checked || 0} IOCs |
                        {lastCorr.matched_campaigns?.length || 0} campaign(s) matched |
                        {lastCorr.alerts?.length || 0} new alert(s) |
                        {lastCorr.live_intel?.length || 0} AbuseIPDB lookup(s) |
                        {lastCorr.otx_intel?.length || 0} OTX lookup(s)
                    </div>
                    {lastCorr.message && (
                        <div style={s.corrMessage}>{lastCorr.message}</div>
                    )}
                    {lastCorr.matched_campaigns?.map(c => (
                        <div key={c.campaign_id} style={s.campMatch}>
                            <span style={s.campName}>{c.campaign_name}</span>
                            <span style={s.campActor}>Actor: {c.actor_name}</span>
                            {c.source && <span style={s.campActor}>Source: {c.source}</span>}
                            <span style={s.campCount}>{c.matched_count} IPs</span>
                            {c.live_intel?.length > 0 && (
                                <div style={s.matchedIps}>
                                    {c.live_intel.map((item) => `${item.value}: ${item.source || "intel"} ${item.abuse_score ?? item.pulse_count ?? ""}`).join(" | ")}
                                </div>
                            )}
                            <div style={s.matchedIps}>{c.matched_ips?.join(" · ")}</div>
                        </div>
                    ))}
                </div>
            )}

            <div style={s.grid}>
                <div>
                    <div style={s.sectionTitle}>Live Alert Stream (SSE → Redis Pub/Sub)</div>
                    {liveAlerts.length === 0 && (
                        <div style={{ ...s.card, textAlign: "center" }}>
                            <p style={s.empty}>Run correlation to generate alerts. They appear here instantly via SSE.</p>
                        </div>
                    )}
                    {liveAlerts.map((a, i) => (
                        <div
                            key={i}
                            style={{
                                ...s.alertCard,
                                border: `2px solid ${SEV_COLOR[a.severity] || theme.cardBorder}`,
                                background: SEV_BG[a.severity] || theme.cardBg
                            }}
                        >
                            <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 6 }}>
                                <span style={{ ...s.sevBadge, background: SEV_COLOR[a.severity], color: "#fff" }}>
                                    {a.severity || "alert"}
                                </span>
                                <span style={s.alertTitle}>{a.campaign_name || a.type}</span>
                                <span style={s.alertTs}>
                                    {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : ""}
                                </span>
                            </div>
                            {a.actor_name && (
                                <div style={s.alertMeta}>Actor: {a.actor_name} · {a.matched_count} IOCs matched</div>
                            )}
                            {a.matched_ips && (
                                <div style={s.alertIps}>{a.matched_ips.join(" · ")}</div>
                            )}
                        </div>
                    ))}
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                    <div style={s.card}>
                        <div style={s.cardTitle}>
                            Active Campaigns
                            <span style={s.dbTag}>Redis</span>
                        </div>
                        {activeCampaigns.length === 0 && <p style={s.empty}>None yet</p>}
                        {activeCampaigns.map(c => (
                            <div key={c} style={s.campRow}>
                                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                    <span style={{
                                        width: 8,
                                        height: 8,
                                        borderRadius: "50%",
                                        background: theme.error,
                                        boxShadow: `0 0 6px ${theme.error}80`,
                                    }} />
                                    <span style={{ fontSize: 12, fontFamily: "monospace", color: theme.textPrimary }}>{c}</span>
                                </div>
                            </div>
                        ))}
                    </div>

                    <div style={s.card}>
                        <div style={s.cardTitle}>
                            Alert History
                            <span style={{ ...s.dbTag, background: theme.infoBg, color: theme.info }}>MongoDB</span>
                        </div>
                        {alerts.slice(0, 5).map(a => (
                            <div key={a._id} style={{ padding: "10px 0", borderBottom: `1px solid ${theme.cardBorder}` }}>
                                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                                    <span style={{
                                        ...s.sevBadge,
                                        background: SEV_COLOR[a.severity] || theme.textMuted,
                                        color: "#fff",
                                        fontSize: 9
                                    }}>
                                        {a.severity}
                                    </span>
                                    <span style={{ fontSize: 12, color: theme.textPrimary }}>{a.title}</span>
                                </div>
                                <div style={{ fontSize: 11, color: theme.textMuted, marginTop: 4 }}>
                                    {new Date(a.createdAt).toLocaleString()}
                                </div>
                            </div>
                        ))}
                        {alerts.length === 0 && <p style={s.empty}>No alerts yet</p>}
                    </div>
                </div>
            </div>

            <style>{`
                @keyframes pulse {
                    0%, 100% { opacity: 1; }
                    50% { opacity: 0.5; }
                }
            `}</style>
        </div>
    );
}
