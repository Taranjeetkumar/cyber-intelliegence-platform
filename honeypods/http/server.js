const http = require("http");
const { emitEvent, normalizeIp } = require("./base/emitEvent");

const PORT = Number(process.env.PORT || 80);

const server = http.createServer((req, res) => {
  const sourceIp = normalizeIp(req.socket.remoteAddress);
  const chunks = [];

  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    const body = Buffer.concat(chunks).toString("utf8").slice(0, 512);
    emitEvent({
      sourceIp,
      service: "http",
      protocol: "tcp",
      destinationPort: 80,
      eventType: "http_request",
      method: req.method,
      path: req.url,
      userAgent: req.headers["user-agent"] || "",
      payload: body,
      severity: req.url.includes("admin") || req.url.includes("wp-") ? "high" : "medium",
    });

    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end("<!doctype html><title>Apache2 Ubuntu Default Page</title><h1>It works!</h1>");
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`HTTP honeypod listening on ${PORT}`);
});
