import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
    fetchTags, searchIOCs, fetchStats, fetchBreakdown,
    setFilter, selectTags, selectResults, selectStats,
    selectBreakdown, selectFilters, selectTSStatus
} from "./threatSearchSlice";

const CONF_COLOR = (c) => c >= 80 ? "#A32D2D" : c >= 60 ? "#854F0B" : "#3B6D11";
const TYPE_COLOR = { ip: "#185FA5", domain: "#3B6D11", hash: "#993C1D", url: "#534AB7" };

export default function ThreatSearchPage() {
    const dispatch = useDispatch();
    const tags = useSelector(selectTags);
    const results = useSelector(selectResults);
    const stats = useSelector(selectStats);
    const breakdown = useSelector(selectBreakdown);
    const filters = useSelector(selectFilters);
    const status = useSelector(selectTSStatus);

    useEffect(() => {
        dispatch(fetchTags());
        dispatch(fetchBreakdown());
        dispatch(fetchStats(""));
    }, []);

    const handleSearch = () => {
        const q = {};
        if (filters.tag) q.tag = filters.tag;
        if (filters.minConfidence) q.minConfidence = filters.minConfidence;
        if (filters.days) q.days = filters.days;
        if (filters.type) q.type = filters.type;
        dispatch(searchIOCs(q));
        dispatch(fetchStats(filters.tag));
    };

    return (
        <div style={s.page}>
            <div style={s.header}>
                <div>
                    <h2 style={s.title}>UC3 — Search Threat Reports</h2>
                    <p style={s.sub}>MongoDB compound queries · aggregation pipeline · $in · $gte</p>
                </div>
            </div>

            {/* Filter bar */}
            <div style={s.filterBar}>
                <div style={s.filterGroup}>
                    <label style={s.label}>Tag / Actor</label>
                    <select style={s.select} value={filters.tag} onChange={e => dispatch(setFilter({ tag: e.target.value }))}>
                        <option value="">All tags</option>
                        {tags.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                </div>
                <div style={s.filterGroup}>
                    <label style={s.label}>IOC Type</label>
                    <select style={s.select} value={filters.type} onChange={e => dispatch(setFilter({ type: e.target.value }))}>
                        <option value="">All types</option>
                        {["ip", "domain", "hash", "url"].map(t => <option key={t}>{t}</option>)}
                    </select>
                </div>
                <div style={s.filterGroup}>
                    <label style={s.label}>Min confidence</label>
                    <input style={s.input} type="number" min="0" max="100" value={filters.minConfidence}
                        onChange={e => dispatch(setFilter({ minConfidence: e.target.value }))} placeholder="0" />
                </div>
                <div style={s.filterGroup}>
                    <label style={s.label}>Last N days</label>
                    <input style={s.input} type="number" min="1" value={filters.days}
                        onChange={e => dispatch(setFilter({ days: e.target.value }))} placeholder="any" />
                </div>
                <button style={s.btn} onClick={handleSearch} disabled={status === "loading"}>
                    {status === "loading" ? "Searching…" : "Search →"}
                </button>
            </div>

            <div style={s.grid}>
                {/* Results */}
                <div>
                    <div style={s.sectionTitle}>Results ({results.length})</div>
                    {results.length === 0 && status !== "loading" && <p style={s.empty}>Run a search above</p>}
                    {results.map((ioc) => (
                        <div key={ioc._id} style={s.resultRow}>
                            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
                                <span style={{ ...s.typeBadge, background: (TYPE_COLOR[ioc.type] || "#888") + "22", color: TYPE_COLOR[ioc.type] || "#888", border: `1px solid ${(TYPE_COLOR[ioc.type] || "#888")}44` }}>{ioc.type}</span>
                                <span style={s.iocValue}>{ioc.value}</span>
                                <span style={{ ...s.conf, color: CONF_COLOR(ioc.confidence) }}>{ioc.confidence}%</span>
                            </div>
                            <div style={s.tagRow}>
                                {ioc.tags?.map(t => <span key={t} style={s.tag}>{t}</span>)}
                            </div>
                            {ioc.enrichment && (
                                <div style={s.enrich}>
                                    {ioc.enrichment.whois_country && <span>🌍 {ioc.enrichment.whois_country}</span>}
                                    {ioc.enrichment.virustotal_score && <span>🔴 VT: {ioc.enrichment.virustotal_score}</span>}
                                    {ioc.enrichment.asn && <span>📡 {ioc.enrichment.asn}</span>}
                                </div>
                            )}
                            <div style={s.dates}>last seen: {ioc.last_seen ? new Date(ioc.last_seen).toLocaleDateString() : "—"} · source: {ioc.source}</div>
                        </div>
                    ))}
                </div>

                {/* Stats sidebar */}
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    {/* Type breakdown */}
                    <div style={s.card}>
                        <div style={s.cardTitle}>IOC type breakdown <span style={s.dbTag}>$group</span></div>
                        {breakdown.map(b => (
                            <div key={b._id} style={s.statRow}>
                                <span style={{ ...s.typeBadge, background: (TYPE_COLOR[b._id] || "#888") + "22", color: TYPE_COLOR[b._id] || "#888", border: `1px solid ${(TYPE_COLOR[b._id] || "#888")}44` }}>{b._id}</span>
                                <span style={s.statCount}>{b.count}</span>
                            </div>
                        ))}
                    </div>

                    {/* Source stats */}
                    <div style={s.card}>
                        <div style={s.cardTitle}>Top sources {filters.tag && `(${filters.tag})`} <span style={s.dbTag}>aggregate</span></div>
                        {stats.length === 0 && <p style={s.empty}>Run search with a tag</p>}
                        {stats.map(s2 => (
                            <div key={s2._id} style={s.statRow}>
                                <span style={{ fontSize: 12, color: "#2C2C2A", fontFamily: "monospace" }}>{s2._id || "unknown"}</span>
                                <div style={{ textAlign: "right" }}>
                                    <div style={{ fontSize: 14, fontWeight: 700, color: "#2E4057" }}>{s2.count}</div>
                                    <div style={{ fontSize: 10, color: "#888780" }}>avg {Math.round(s2.avg_confidence)}%</div>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* MongoDB query display */}
                    <div style={{ ...s.card, background: "#1E1E2E" }}>
                        <div style={{ ...s.cardTitle, color: "#CDD6F4" }}>MongoDB query</div>
                        <pre style={{ fontSize: 10, color: "#A6E3A1", whiteSpace: "pre-wrap", lineHeight: 1.6 }}>{`db.ioc_records.find({
  ${filters.tag ? `tags: { $in: ["${filters.tag}"] },\n  ` : ""}${filters.minConfidence ? `confidence: { $gte: ${filters.minConfidence} },\n  ` : ""}${filters.days ? `last_seen: { $gte: new Date()\n    // -${filters.days} days\n  }` : "..."}
}).sort({ confidence: -1 })`}</pre>
                    </div>
                </div>
            </div>
        </div>
    );
}

const s = {
    page: { padding: 20, fontFamily: "system-ui,sans-serif" },
    header: { marginBottom: 16 },
    title: { fontSize: 18, fontWeight: 700, color: "#2C2C2A", margin: 0 },
    sub: { fontSize: 12, color: "#888780", margin: "4px 0 0" },
    filterBar: { display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end", background: "#F9F8F5", border: "1px solid #D3D1C7", borderRadius: 10, padding: "14px 16px", marginBottom: 20 },
    filterGroup: { display: "flex", flexDirection: "column", gap: 4 },
    label: { fontSize: 11, fontWeight: 600, color: "#5F5E5A", textTransform: "uppercase", letterSpacing: ".06em" },
    select: { padding: "7px 10px", fontSize: 13, border: "1px solid #B4B2A9", borderRadius: 6, background: "#fff", minWidth: 140 },
    input: { padding: "7px 10px", fontSize: 13, border: "1px solid #B4B2A9", borderRadius: 6, width: 100 },
    btn: { padding: "8px 18px", background: "#2E4057", color: "#fff", border: "none", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 600, alignSelf: "flex-end" },
    grid: { display: "grid", gridTemplateColumns: "1fr 300px", gap: 16, alignItems: "start" },
    sectionTitle: { fontSize: 12, fontWeight: 700, color: "#5F5E5A", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 10 },
    empty: { fontSize: 12, color: "#888780", fontStyle: "italic", textAlign: "center", padding: "20px 0" },
    resultRow: { background: "#FAFAF8", border: "1px solid #D3D1C7", borderRadius: 8, padding: 12, marginBottom: 8 },
    typeBadge: { fontSize: 10, fontWeight: 600, padding: "2px 7px", borderRadius: 4, textTransform: "uppercase" },
    iocValue: { fontSize: 13, fontFamily: "monospace", fontWeight: 600, color: "#2C2C2A", flex: 1 },
    conf: { fontSize: 12, fontWeight: 700 },
    tagRow: { display: "flex", gap: 4, flexWrap: "wrap", margin: "4px 0" },
    tag: { fontSize: 10, background: "#EEEDFE", color: "#3C3489", padding: "1px 6px", borderRadius: 3 },
    enrich: { display: "flex", gap: 12, fontSize: 11, color: "#5F5E5A", margin: "4px 0" },
    dates: { fontSize: 10, color: "#888780", marginTop: 4 },
    card: { background: "#FAFAF8", border: "1px solid #D3D1C7", borderRadius: 10, padding: 14 },
    cardTitle: { fontSize: 11, fontWeight: 700, color: "#444441", marginBottom: 10, display: "flex", alignItems: "center", gap: 6 },
    dbTag: { fontSize: 9, background: "#EAF3DE", color: "#27500A", padding: "1px 6px", borderRadius: 3, fontFamily: "monospace", fontWeight: 400 },
    statRow: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: "1px solid #F1EFE8" },
    statCount: { fontSize: 14, fontWeight: 700, color: "#2E4057" },
};