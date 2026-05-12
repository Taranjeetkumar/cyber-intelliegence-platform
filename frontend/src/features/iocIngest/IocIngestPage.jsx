import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";

// ── Slice ─────────────────────────────────────────────────────────────────────
export const ingestOne  = createAsyncThunk("iocIngest/one",   async(data)=>(await axios.post("/api/ingest/one",data)).data);
export const fetchStats = createAsyncThunk("iocIngest/stats", async()=>(await axios.get("/api/ingest/stats")).data);

const slice = createSlice({
  name:"iocIngest",
  initialState:{results:[],stats:{},status:"idle",error:null},
  reducers:{clearResults:(s)=>{s.results=[];s.status="idle";}},
  extraReducers:(b)=>{
    b.addCase(ingestOne.pending,(s)=>{s.status="loading";});
    b.addCase(ingestOne.fulfilled,(s,a)=>{s.results=[a.payload,...s.results.slice(0,9)];s.status="succeeded";});
    b.addCase(ingestOne.rejected,(s,a)=>{s.status="failed";s.error=a.error.message;});
    b.addCase(fetchStats.fulfilled,(s,a)=>{s.stats=a.payload;});
  },
});

export const { clearResults } = slice.actions;
export const selectIngestResults = (s)=>s.iocIngest.results;
export const selectIngestStats   = (s)=>s.iocIngest.stats;
export const selectIngestStatus  = (s)=>s.iocIngest.status;
export default slice.reducer;

// ── Page ─────────────────────────────────────────────────────────────────────
const BATCH_EXAMPLES = [
  {value:"10.10.10.99",type:"ip",tags:["APT28","lateral-movement"],confidence:75,source:"manual"},
  {value:"malware-drop.xyz",type:"domain",tags:["ransomware","C2"],confidence:88,source:"threatfeed"},
  {value:"d41d8cd98f00b204e9800998ecf8427e",type:"hash",tags:["Emotet"],confidence:95,source:"sandbox"},
];

export function IocIngestPage() {
  const dispatch = useDispatch();
  const results  = useSelector(selectIngestResults);
  const stats    = useSelector(selectIngestStats);
  const status   = useSelector(selectIngestStatus);

  const [form, setForm] = useState({value:"",type:"ip",tags:"",confidence:70,source:"manual"});

  useEffect(()=>{ dispatch(fetchStats()); },[]);

  const handleIngest = () => {
    dispatch(ingestOne({
      ...form,
      tags: form.tags.split(",").map(t=>t.trim()).filter(Boolean),
      confidence: Number(form.confidence),
    })).then(()=>dispatch(fetchStats()));
  };

  const handleBatch = () => {
    BATCH_EXAMPLES.forEach(ioc => dispatch(ingestOne(ioc)));
    setTimeout(()=>dispatch(fetchStats()), 1000);
  };

  const up = (k,v) => setForm(f=>({...f,[k]:v}));

  return (
    <div style={s.page}>
      <div style={s.header}>
        <div><h2 style={s.title}>UC5 — Ingest &amp; Enrich IOC Feed</h2>
          <p style={s.sub}>MongoDB $setOnInsert upsert · Neo4j MERGE ON CREATE/ON MATCH</p></div>
      </div>

      <div style={s.grid}>
        <div>
          {/* Manual ingest form */}
          <div style={s.card}>
            <div style={s.cardTitle}>Manual IOC ingest</div>
            <div style={s.formGrid}>
              <div><label style={s.label}>Value</label>
                <input style={s.input} value={form.value} onChange={e=>up("value",e.target.value)} placeholder="203.0.113.99"/></div>
              <div><label style={s.label}>Type</label>
                <select style={s.select} value={form.type} onChange={e=>up("type",e.target.value)}>
                  {["ip","domain","hash","url"].map(t=><option key={t}>{t}</option>)}
                </select></div>
              <div><label style={s.label}>Tags (comma separated)</label>
                <input style={s.input} value={form.tags} onChange={e=>up("tags",e.target.value)} placeholder="APT29, c2"/></div>
              <div><label style={s.label}>Confidence (0-100)</label>
                <input style={s.input} type="number" min="0" max="100" value={form.confidence} onChange={e=>up("confidence",e.target.value)}/></div>
              <div><label style={s.label}>Source</label>
                <input style={s.input} value={form.source} onChange={e=>up("source",e.target.value)} placeholder="abuse.ch"/></div>
            </div>
            <div style={{display:"flex",gap:8,marginTop:14}}>
              <button style={s.btn} onClick={handleIngest} disabled={!form.value||status==="loading"}>
                {status==="loading"?"Ingesting…":"Ingest IOC →"}</button>
              <button style={s.btnOutline} onClick={handleBatch}>Ingest 3 examples</button>
            </div>
          </div>

          {/* Results feed */}
          {results.length>0 && (
            <div style={{marginTop:16}}>
              <div style={s.sectionTitle}>Recent ingestions</div>
              {results.map((r,i)=>(
                <div key={i} style={s.resultRow}>
                  <div style={{display:"flex",gap:8,alignItems:"center"}}>
                    <span style={{...s.statusBadge,background:r.status==="created"?"#EAF3DE":"#EEEDFE",color:r.status==="created"?"#27500A":"#3C3489"}}>{r.status}</span>
                    <span style={s.iocVal}>{r.value}</span>
                    <span style={s.typeTag}>{r.type}</span>
                  </div>
                  <div style={s.enrichRow}>
                    🌍 {r.enrichment?.whois_country} · 🔴 VT: {r.enrichment?.virustotal_score} · 📡 {r.enrichment?.asn}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div style={{display:"flex",flexDirection:"column",gap:12}}>
          {/* Stats */}
          <div style={s.card}>
            <div style={s.cardTitle}>Ingestion counters <span style={s.dbTag}>Redis INCR</span></div>
            {Object.entries(stats).filter(([k])=>k!=="total").map(([k,v])=>(
              <div key={k} style={s.statRow}>
                <span style={{fontSize:12,fontFamily:"monospace",color:"#2C2C2A"}}>{k}</span>
                <span style={{fontSize:16,fontWeight:700,color:"#185FA5"}}>{v}</span>
              </div>
            ))}
            {stats.total!=null&&<div style={{...s.statRow,borderTop:"2px solid #D3D1C7",marginTop:4}}>
              <span style={{fontSize:12,fontWeight:700}}>total</span>
              <span style={{fontSize:18,fontWeight:700,color:"#2E4057"}}>{stats.total}</span>
            </div>}
          </div>

          {/* How it works */}
          <div style={{...s.card,background:"#1E1E2E"}}>
            <div style={{...s.cardTitle,color:"#CDD6F4"}}>What happens per IOC</div>
            {[
              ["1","Check MongoDB","findOne by value+type"],
              ["2","If new → Enrich","WHOIS + VirusTotal API"],
              ["3","MongoDB upsert","$setOnInsert preserves first_seen"],
              ["4","Neo4j MERGE","creates node only if not exists"],
              ["5","Redis INCR","stats:ingested:{type}++"],
            ].map(([n,t,d])=>(
              <div key={n} style={{display:"flex",gap:8,marginBottom:8}}>
                <span style={{width:18,height:18,borderRadius:"50%",background:"#313244",color:"#CDD6F4",fontSize:10,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>{n}</span>
                <div><div style={{fontSize:12,fontWeight:600,color:"#CDD6F4"}}>{t}</div>
                  <div style={{fontSize:10,color:"#6C7086"}}>{d}</div></div>
              </div>
            ))}
          </div>

          <div style={{...s.card,background:"#1E1E2E"}}>
            <div style={{...s.cardTitle,color:"#CDD6F4"}}>Key MongoDB operator</div>
            <pre style={{fontSize:10,color:"#A6E3A1",whiteSpace:"pre-wrap",lineHeight:1.6}}>{`updateOne(
  { value, type },
  {
    $set: { last_seen, tags },
    $setOnInsert: {
      first_seen: now
      // only on NEW docs
    }
  },
  { upsert: true }
)`}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}

const s = {
  page:{padding:20,fontFamily:"system-ui,sans-serif"},
  header:{marginBottom:20},
  title:{fontSize:18,fontWeight:700,color:"#2C2C2A",margin:0},
  sub:{fontSize:12,color:"#888780",margin:"4px 0 0"},
  grid:{display:"grid",gridTemplateColumns:"1fr 280px",gap:16,alignItems:"start"},
  card:{background:"#FAFAF8",border:"1px solid #D3D1C7",borderRadius:10,padding:16},
  cardTitle:{fontSize:12,fontWeight:700,color:"#444441",marginBottom:12,display:"flex",alignItems:"center",gap:6},
  dbTag:{fontSize:9,background:"#EAF3DE",color:"#27500A",padding:"1px 6px",borderRadius:3,fontFamily:"monospace",fontWeight:400},
  formGrid:{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12},
  label:{display:"block",fontSize:11,fontWeight:600,color:"#5F5E5A",textTransform:"uppercase",letterSpacing:".06em",marginBottom:4},
  input:{padding:"7px 10px",fontSize:13,border:"1px solid #B4B2A9",borderRadius:6,width:"100%",boxSizing:"border-box"},
  select:{padding:"7px 10px",fontSize:13,border:"1px solid #B4B2A9",borderRadius:6,width:"100%"},
  btn:{padding:"8px 18px",background:"#534AB7",color:"#fff",border:"none",borderRadius:6,cursor:"pointer",fontSize:13,fontWeight:600},
  btnOutline:{padding:"8px 18px",background:"transparent",color:"#534AB7",border:"1px solid #534AB7",borderRadius:6,cursor:"pointer",fontSize:13,fontWeight:600},
  sectionTitle:{fontSize:12,fontWeight:700,color:"#5F5E5A",textTransform:"uppercase",letterSpacing:".06em",marginBottom:8},
  resultRow:{background:"#FAFAF8",border:"1px solid #D3D1C7",borderRadius:8,padding:10,marginBottom:8},
  statusBadge:{fontSize:10,fontWeight:700,padding:"2px 8px",borderRadius:4,textTransform:"uppercase"},
  iocVal:{fontSize:13,fontFamily:"monospace",fontWeight:600,color:"#2C2C2A",flex:1},
  typeTag:{fontSize:10,background:"#E6F1FB",color:"#0C447C",padding:"1px 6px",borderRadius:3},
  enrichRow:{fontSize:11,color:"#5F5E5A",marginTop:4,display:"flex",gap:12},
  statRow:{display:"flex",justifyContent:"space-between",padding:"5px 0",borderBottom:"1px solid #F1EFE8"},
};
