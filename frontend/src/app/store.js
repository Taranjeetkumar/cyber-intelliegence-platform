import { configureStore } from "@reduxjs/toolkit";
import investigationReducer from "../features/investigation/investigationSlice";
import iocMonitorReducer    from "../features/iocMonitor/iocMonitorSlice";
import threatSearchReducer  from "../features/threatSearch/threatSearchSlice";
import deviceRiskReducer    from "../features/deviceRisk/DeviceRiskPage";
import iocIngestReducer     from "../features/iocIngest/IocIngestPage";
import campaignAlertReducer from "../features/campaignAlert/CampaignAlertPage";

export const store = configureStore({
  reducer: {
    investigation: investigationReducer,
    iocMonitor:    iocMonitorReducer,
    threatSearch:  threatSearchReducer,
    deviceRisk:    deviceRiskReducer,
    iocIngest:     iocIngestReducer,
    campaignAlert: campaignAlertReducer,
  },
});

