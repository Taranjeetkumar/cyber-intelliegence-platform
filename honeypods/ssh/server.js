const net = require("net");
const { emitEvent, normalizeIp } = require("./base/emitEvent");

const PORT = Number(process.env.PORT || 22);

const server = net.createServer((socket) => {
  const sourceIp = normalizeIp(socket.remoteAddress);
  let buffer = "";

  socket.write("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n");

  socket.on("data", (chunk) => {
    buffer += chunk.toString("utf8").replace(/[^\x20-\x7E\r\n\t]/g, "").slice(0, 512);
    emitEvent({
      sourceIp,
      service: "ssh",
      protocol: "tcp",
      destinationPort: 22,
      eventType: "connection_attempt",
      payload: buffer.slice(0, 256),
      severity: "medium",
    });
    socket.end("Protocol mismatch.\r\n");
  });

  socket.on("close", () => {
    if (!buffer) {
      emitEvent({
        sourceIp,
        service: "ssh",
        protocol: "tcp",
        destinationPort: 22,
        eventType: "connection_opened",
        severity: "low",
      });
    }
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`SSH honeypod listening on ${PORT}`);
});
