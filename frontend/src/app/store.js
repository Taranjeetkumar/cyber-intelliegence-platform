import { configureStore } from "@reduxjs/toolkit";
import investigationReducer from "../features/investigation/investigationSlice";

export const store = configureStore({
  reducer: {
    investigation: investigationReducer,
  },
});
