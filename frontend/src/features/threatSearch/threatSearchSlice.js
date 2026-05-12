import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";

export const fetchTags = createAsyncThunk("threatSearch/fetchTags", async () => (await axios.get("/api/search/tags")).data);
export const searchIOCs = createAsyncThunk("threatSearch/searchIOCs", async (q) => (await axios.get("/api/search/iocs", { params: q })).data);
export const fetchStats = createAsyncThunk("threatSearch/fetchStats", async (tag) => (await axios.get("/api/search/stats", { params: { tag } })).data);
export const fetchBreakdown = createAsyncThunk("threatSearch/fetchBreakdown", async () => (await axios.get("/api/search/breakdown")).data);

const slice = createSlice({
    name: "threatSearch",
    initialState: { tags: [], results: [], stats: [], breakdown: [], filters: { tag: "", minConfidence: 0, days: "", type: "" }, status: "idle", error: null },
    reducers: {
        setFilter: (s, a) => { s.filters = { ...s.filters, ...a.payload }; },
        clearResults: (s) => { s.results = []; s.status = "idle"; },
    },
    extraReducers: (b) => {
        b.addCase(fetchTags.fulfilled, (s, a) => { s.tags = a.payload; });
        b.addCase(searchIOCs.pending, (s) => { s.status = "loading"; });
        b.addCase(searchIOCs.fulfilled, (s, a) => { s.results = a.payload; s.status = "succeeded"; });
        b.addCase(searchIOCs.rejected, (s, a) => { s.status = "failed"; s.error = a.payload; });
        b.addCase(fetchStats.fulfilled, (s, a) => { s.stats = a.payload; });
        b.addCase(fetchBreakdown.fulfilled, (s, a) => { s.breakdown = a.payload; });
    },
});

export const { setFilter, clearResults } = slice.actions;
export const selectTags = (s) => s.threatSearch.tags;
export const selectResults = (s) => s.threatSearch.results;
export const selectStats = (s) => s.threatSearch.stats;
export const selectBreakdown = (s) => s.threatSearch.breakdown;
export const selectFilters = (s) => s.threatSearch.filters;
export const selectTSStatus = (s) => s.threatSearch.status;
export default slice.reducer;
