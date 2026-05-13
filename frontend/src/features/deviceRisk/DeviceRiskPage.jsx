import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";
import { useDispatch, useSelector } from "react-redux";
import { useEffect, useState } from "react";

// ── Slice ─────────────────────────────────────────────────────────────────────
export const fetchAtRiskDevices = createAsyncThunk("deviceRisk/fetch",
    async (minCvss = 7.0) => (await axios.get(`/api/devices/at-risk?minCvss=${minCvss}`)).data
);

const slice = createSlice({
    name: "deviceRisk",
    initialState: { devices: [], status: "idle", error: null },
    reducers: {},
    extraReducers: (b) => {
        b.addCase(fetchAtRiskDevices.pending, (s) => { s.status = "loading"; });
        b.addCase(fetchAtRiskDevices.fulfilled, (s, a) => { s.devices = a.payload; s.status = "succeeded"; });
        b.addCase(fetchAtRiskDevices.rejected, (s, a) => { s.status = "failed"; s.error = a.payload; });
    },
});

export const selectDevices = (s) => s.deviceRisk.devices;
export const selectDRStatus = (s) => s.deviceRisk.status;
export default slice.reducer;

// ── Page ─────────────────────────────────────────────────────────────────────
const RISK_COLOR = (r) => r >= 80 ? "#A32D2D" : r >= 60 ? "#854F0B" : r >= 40 ? "#534AB7" : "#3B6D11";

export function DeviceRiskPage() {
    const dispatch = useDispatch();
    const devices = useSelector(selectDevices);
    const status = useSelector(selectDRStatus);
    const [minCvss, setMinCvss] = useState(7.0);
    const [selected, setSelected] = useState(null);

    useEffect(() => { dispatch(fetchAtRiskDevices(minCvss)); }, []);

    return (
        <div style={s.page}>
            <div style={s.header}>
                <div><h2 style={s.title}>At-Risk Devices</h2>
                    </div>
                <div style={{ display: "flex", gap: 8, alignItems: "flex-end" }}>
                    <div><label style={s.label}>Min CVSS</label>
                        <input style={s.input} type="number" min="0" max="10" step="0.5" value={minCvss}
                            onChange={e => setMinCvss(e.target.value)} /></div>
                    <button style={s.btn} onClick={() => dispatch(fetchAtRiskDevices(minCvss))}
                        disabled={status === "loading"}>{status === "loading" ? "Loading…" : "Scan →"}</button>
                </div>
            </div>

            {devices.length === 0 && status !== "loading" &&
                <p style={s.empty}>No devices found. Lower the Min CVSS or run the seed script.</p>}

            <div style={s.grid}>
                {/* Device list */}
                <div>
                    {devices.map(d => (
                        <div key={d.hostname} style={{ ...s.deviceCard, borderColor: selected?.hostname === d.hostname ? "#2E4057" : "#D3D1C7" }}
                            onClick={() => setSelected(d)}>
                            <div style={s.deviceHeader}>
                                <div>
                                    <div style={s.hostname}>{d.hostname}</div>
                                    <div style={s.deviceMeta}>{d.ip} · {d.os}</div>
                                </div>
                                <div style={{ textAlign: "right" }}>
                                    <div style={{ ...s.riskScore, color: RISK_COLOR(d.final_risk) }}>{d.final_risk}</div>
                                    <div style={{ fontSize: 10, color: "#888780" }}>{d.redis_risk != null ? "Redis cached" : "computed"}</div>
                                </div>
                            </div>
                            <div style={s.vulnList}>
                                {d.vulnerabilities?.map((v, i) => (
                                    <div key={i} style={s.vulnRow}>
                                        <span style={s.cveId}>{v.cve_id}</span>
                                        <span style={{ ...s.cvss, color: RISK_COLOR(v.cvss_score * 10) }}>CVSS {v.cvss_score}</span>
                                        <span style={s.svc}>{v.service}:{v.port}</span>
                                        <span style={s.exploit}>{v.exploit_module?.split("/").pop()}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>

                {/* Detail panel */}
                <div style={s.detailPanel}>
                    {!selected ? <p style={s.empty}>Click a device to see details</p> : (
                        <>
                            <div style={s.detailTitle}>{selected.hostname}</div>
                            <div style={s.detailMeta}>{selected.ip} · {selected.os}</div>
                            <div style={s.infoBox}>
                                <div style={s.infoRow}><span>Final risk</span><strong style={{ color: RISK_COLOR(selected.final_risk) }}>{selected.final_risk}</strong></div>
                                <div style={s.infoRow}><span>Redis cached</span><span>{selected.redis_risk != null ? `${selected.redis_risk} (TTL key)` : "expired / not set"}</span></div>
                                <div style={s.infoRow}><span>Vulnerabilities</span><span>{selected.vuln_count}</span></div>
                            </div>
                            {/* <div style={{ fontSize: 11, fontWeight: 700, color: "#5F5E5A", textTransform: "uppercase", letterSpacing: ".06em", margin: "12px 0 6px" }}>Neo4j query used</div>
                            <pre style={s.cypher}>{`MATCH (d:Device)-[:HAS_PORT]->(p:Port)
  -[:RUNS]->(s:Service)
  -[:VULNERABLE_TO]->(c:CVE)
  -[:HAS_EXPLOIT]->(e:Exploit)
WHERE c.cvss_score >= ${minCvss}
RETURN d.hostname, c.cve_id,
  c.cvss_score, e.module_name`}</pre> */}
                        </>
                    )}
                </div>
            </div>
        </div>
    );
}

const s = {
    page: { padding: 20, fontFamily: "system-ui,sans-serif" },
    header: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20, flexWrap: "wrap", gap: 12 },
    title: { fontSize: 18, fontWeight: 700, color: "#2C2C2A", margin: 0 },
    sub: { fontSize: 12, color: "#888780", margin: "4px 0 0" },
    label: { display: "block", fontSize: 11, fontWeight: 600, color: "#5F5E5A", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 4 },
    input: { padding: "7px 10px", fontSize: 13, border: "1px solid #B4B2A9", borderRadius: 6, width: 80 },
    btn: { padding: "8px 18px", background: "#993C1D", color: "#fff", border: "none", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 600 },
    empty: { fontSize: 13, color: "#888780", fontStyle: "italic", textAlign: "center", padding: "40px 0" },
    grid: { display: "grid", gridTemplateColumns: "1fr 280px", gap: 16, alignItems: "start" },
    deviceCard: { background: "#FAFAF8", border: "2px solid #D3D1C7", borderRadius: 10, padding: 14, marginBottom: 10, cursor: "pointer", transition: "border-color .15s" },
    deviceHeader: { display: "flex", justifyContent: "space-between", marginBottom: 8 },
    hostname: { fontSize: 14, fontWeight: 700, color: "#2C2C2A", fontFamily: "monospace" },
    deviceMeta: { fontSize: 11, color: "#888780" },
    riskScore: { fontSize: 26, fontWeight: 700, fontFamily: "monospace" },
    vulnList: { display: "flex", flexDirection: "column", gap: 4 },
    vulnRow: { display: "flex", gap: 8, alignItems: "center", padding: "4px 8px", background: "#F5F3EE", borderRadius: 6, flexWrap: "wrap" },
    cveId: { fontSize: 11, fontFamily: "monospace", fontWeight: 600, color: "#2C2C2A" },
    cvss: { fontSize: 11, fontWeight: 700 },
    svc: { fontSize: 10, color: "#534AB7", fontFamily: "monospace" },
    exploit: { fontSize: 10, color: "#888780", fontFamily: "monospace", marginLeft: "auto" },
    detailPanel: { background: "#FAFAF8", border: "1px solid #D3D1C7", borderRadius: 10, padding: 16, position: "sticky", top: 20 },
    detailTitle: { fontSize: 15, fontWeight: 700, color: "#2C2C2A", fontFamily: "monospace" },
    detailMeta: { fontSize: 12, color: "#888780", marginBottom: 12 },
    infoBox: { background: "#F5F3EE", borderRadius: 6, padding: 10 },
    infoRow: { display: "flex", justifyContent: "space-between", fontSize: 12, padding: "4px 0", borderBottom: "1px solid #E8E6DF" },
    cypher: { fontSize: 10, background: "#1E1E2E", color: "#A6E3A1", padding: 10, borderRadius: 6, whiteSpace: "pre-wrap", lineHeight: 1.6, marginTop: 4 },
};
