/**
 * setupProxy.js — CRA dev-server proxy (loaded automatically by react-scripts).
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The simple "proxy" key in package.json uses http-proxy-middleware internally,
 * but it enables response-buffering by default.  Server-Sent Events (SSE) need
 * every chunk to be flushed to the browser immediately, so a buffered proxy
 * keeps the connection open but the browser never receives the initial
 * "connected" event → the status pill stays stuck on "Connecting…".
 *
 * This file gives us explicit control over the proxy so we can:
 *   1. Disable buffering on /api/alerts/stream (SSE fix).
 *   2. Keep normal proxying for every other /api/* call.
 */

const { createProxyMiddleware } = require("http-proxy-middleware");

module.exports = function (app) {
  const BACKEND = process.env.REACT_APP_BACKEND_URL || process.env.BACKEND_URL || "http://localhost:5050";

  // ── 1. SSE stream — must come BEFORE the catch-all /api rule ──────────────
  app.use(
    "/api/alerts/stream",
    createProxyMiddleware({
      target: BACKEND,
      changeOrigin: true,
      // SSE-specific: do NOT buffer — pass each chunk through immediately.
      selfHandleResponse: false,
      on: {
        proxyReq: (proxyReq) => {
          // Tell the backend we accept an event stream.
          proxyReq.setHeader("Accept", "text/event-stream");
          proxyReq.setHeader("Cache-Control", "no-cache");
        },
        proxyRes: (proxyRes) => {
          // Ensure the proxy itself doesn't buffer.
          proxyRes.headers["x-accel-buffering"] = "no";
          proxyRes.headers["cache-control"] = "no-cache";
        },
      },
    })
  );

  // ── 2. All other API calls ─────────────────────────────────────────────────
  app.use(
    "/api",
    createProxyMiddleware({
      target: BACKEND,
      changeOrigin: true,
    })
  );
};
