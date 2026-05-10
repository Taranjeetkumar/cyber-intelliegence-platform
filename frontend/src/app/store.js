import { configureStore } from "@reduxjs/toolkit";
import investigationReducer from "../features/investigation/investigationSlice";
import threatSearchReducer from "../features/threatSearch/threatSearchSlice";
import deviceRiskReducer from "../features/deviceRisk/DeviceRiskPage";
import campaignAlertReducer from "../features/campaignAlert/CampaignAlertPage";
export const store = configureStore({
  reducer: {
    investigation: investigationReducer,
    threatSearch: threatSearchReducer,
    deviceRisk: deviceRiskReducer,
    campaignAlert: campaignAlertReducer,
  },
});

