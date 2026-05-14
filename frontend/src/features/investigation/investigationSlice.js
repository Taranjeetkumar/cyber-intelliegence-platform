import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";

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

export const fetchHoneypotEvents = createAsyncThunk(
  "investigation/fetchHoneypotEvents",
  async (_, { rejectWithValue }) => {
    try {
      const res = await axios.get("/api/honeypot/events?limit=20");
      return res.data.events;
    } catch (err) {
      return rejectWithValue(err.response?.data?.error || "Failed to fetch honeypot events");
    }
  }
);

const investigationSlice = createSlice({
  name: "investigation",
  initialState: {
    knownIPs: [],
    selectedIP: "",
    result: null,
    selectedNode: null,
    honeypotEvents: [],
    status: "idle",
    liveStatus: "idle",
    error: null,
    liveError: null,
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
    builder
      .addCase(fetchKnownIPs.fulfilled, (state, action) => {
        state.knownIPs = action.payload;
      })
      .addCase(investigateIP.pending, (state) => {
        state.status = "loading";
        state.error = null;
        state.result = null;
        state.selectedNode = null;
      })
      .addCase(investigateIP.fulfilled, (state, action) => {
        state.status = "succeeded";
        state.result = action.payload;
        const nodes = action.payload?.graph?.nodes || [];
        state.selectedNode = nodes.find((node) => node.isRoot) || nodes[0] || null;
      })
      .addCase(investigateIP.rejected, (state, action) => {
        state.status = "failed";
        state.error = action.payload;
      })
      .addCase(fetchHoneypotEvents.pending, (state) => {
        state.liveStatus = "loading";
        state.liveError = null;
      })
      .addCase(fetchHoneypotEvents.fulfilled, (state, action) => {
        state.liveStatus = "succeeded";
        state.honeypotEvents = action.payload;
      })
      .addCase(fetchHoneypotEvents.rejected, (state, action) => {
        state.liveStatus = "failed";
        state.liveError = action.payload;
      });
  },
});

export const { setSelectedIP, setSelectedNode, clearResult } = investigationSlice.actions;

export const selectKnownIPs = (s) => s.investigation.knownIPs;
export const selectSelectedIP = (s) => s.investigation.selectedIP;
export const selectResult = (s) => s.investigation.result;
export const selectSelectedNode = (s) => s.investigation.selectedNode;
export const selectStatus = (s) => s.investigation.status;
export const selectError = (s) => s.investigation.error;
export const selectHoneypotEvents = (s) => s.investigation.honeypotEvents;
export const selectLiveStatus = (s) => s.investigation.liveStatus;
export const selectLiveError = (s) => s.investigation.liveError;

export default investigationSlice.reducer;
