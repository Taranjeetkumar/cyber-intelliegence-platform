import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";

// ── Async thunks ─────────────────────────────────────────────────────────────

export const fetchKnownIPs = createAsyncThunk(
  "investigation/fetchKnownIPs",
  async (_, { rejectWithValue }) => {
    try {
      const res = await axios.get("/api/investigate/known-ips");
      return res.data.ips;
    } catch (err) {
      return rejectWithValue(err.response?.data?.error || "Failed to fetch IPs");
    }
  }
);

export const investigateIP = createAsyncThunk(
  "investigation/investigateIP",
  async (ipValue, { rejectWithValue }) => {
    try {
      const res = await axios.get(`/api/investigate/ip?value=${encodeURIComponent(ipValue)}`);
      return res.data;
    } catch (err) {
      return rejectWithValue(err.response?.data?.error || "Investigation failed");
    }
  }
);

// ── Slice ─────────────────────────────────────────────────────────────────────

const investigationSlice = createSlice({
  name: "investigation",
  initialState: {
    knownIPs: [],
    selectedIP: "",
    result: null,       // { found, graph, mongoDetail, activeCampaigns, stats }
    selectedNode: null, // node the user clicked in the graph
    status: "idle",     // idle | loading | succeeded | failed
    error: null,
  },
  reducers: {
    setSelectedIP: (state, action) => {
      state.selectedIP = action.payload;
    },
    setSelectedNode: (state, action) => {
      state.selectedNode = action.payload;
    },
    clearResult: (state) => {
      state.result = null;
      state.selectedNode = null;
      state.error = null;
      state.status = "idle";
    },
  },
  extraReducers: (builder) => {
    // fetchKnownIPs
    builder
      .addCase(fetchKnownIPs.fulfilled, (state, action) => {
        state.knownIPs = action.payload;
      })

    // investigateIP
      .addCase(investigateIP.pending, (state) => {
        state.status = "loading";
        state.error = null;
        state.result = null;
        state.selectedNode = null;
      })
      .addCase(investigateIP.fulfilled, (state, action) => {
        state.status = "succeeded";
        state.result = action.payload;
      })
      .addCase(investigateIP.rejected, (state, action) => {
        state.status = "failed";
        state.error = action.payload;
      });
  },
});

export const { setSelectedIP, setSelectedNode, clearResult } = investigationSlice.actions;

// ── Selectors ─────────────────────────────────────────────────────────────────
export const selectKnownIPs = (s) => s.investigation.knownIPs;
export const selectSelectedIP = (s) => s.investigation.selectedIP;
export const selectResult = (s) => s.investigation.result;
export const selectSelectedNode = (s) => s.investigation.selectedNode;
export const selectStatus = (s) => s.investigation.status;
export const selectError = (s) => s.investigation.error;

export default investigationSlice.reducer;
