import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";

export const fetchLeaderboard = createAsyncThunk("iocMonitor/fetchLeaderboard", async (_, { rejectWithValue }) => {
    try { return (await axios.get("/api/monitor/leaderboard?limit=10")).data; }
    catch (e) { return rejectWithValue(e.response?.data?.error || e.message); }
});

export const fetchDeviceScores = createAsyncThunk("iocMonitor/fetchDeviceScores", async (_, { rejectWithValue }) => {
    try { return (await axios.get("/api/monitor/device-scores")).data; }
    catch (e) { return rejectWithValue(e.response?.data?.error || e.message); }
});

export const fetchActiveCampaigns = createAsyncThunk("iocMonitor/fetchActiveCampaigns", async (_, { rejectWithValue }) => {
    try { return (await axios.get("/api/monitor/active-campaigns")).data; }
    catch (e) { return rejectWithValue(e.response?.data?.error || e.message); }
});

const slice = createSlice({
    name: "iocMonitor",
    initialState: {
        leaderboard: [],
        deviceScores: [],
        activeCampaigns: [],
        updatedAt: null,
        status: "idle",
        error: null,
    },
    reducers: {},
    extraReducers: (b) => {
        b.addCase(fetchLeaderboard.fulfilled, (s, a) => {
            s.leaderboard = a.payload.leaderboard;
            s.updatedAt = a.payload.updatedAt;
            s.status = "succeeded";
        });
        b.addCase(fetchDeviceScores.fulfilled, (s, a) => { s.deviceScores = a.payload; });
        b.addCase(fetchActiveCampaigns.fulfilled, (s, a) => { s.activeCampaigns = a.payload; });
        b.addCase(fetchLeaderboard.pending, (s) => { s.status = "loading"; });
        b.addCase(fetchLeaderboard.rejected, (s, a) => { s.status = "failed"; s.error = a.payload; });
    },
});

export const selectLeaderboard = (s) => s.iocMonitor.leaderboard;
export const selectDeviceScores = (s) => s.iocMonitor.deviceScores;
export const selectActiveCampaigns = (s) => s.iocMonitor.activeCampaigns;
export const selectMonitorStatus = (s) => s.iocMonitor.status;
export const selectUpdatedAt = (s) => s.iocMonitor.updatedAt;

export default slice.reducer;
