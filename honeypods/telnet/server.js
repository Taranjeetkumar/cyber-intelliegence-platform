const net = require("net");
const { emitEvent, normalizeIp } = require("./base/emitEvent");

const PORT = Number(process.env.PORT || 23);

const server = net.createServer((socket) => {
  const sourceIp = normalizeIp(socket.remoteAddress);
  let stage = "username";
  let username = "";

  socket.write("Ubuntu 20.04 LTS\r\nlogin: ");

  socket.on("data", (chunk) => {
    const value = chunk.toString("utf8").trim().slice(0, 120);

    if (stage === "username") {
      username = value;
      stage = "password";
      socket.write("Password: ");
      return;
    }

    emitEvent({
      sourceIp,
      service: "telnet",
      protocol: "tcp",
      destinationPort: 23,
      eventType: "credential_attempt",
      username,
      password: value,
      severity: "high",
    });
    socket.write("\r\nLogin incorrect\r\nlogin: ");
    stage = "username";
    username = "";
  });

  socket.on("close", () => {
    emitEvent({
      sourceIp,
      service: "telnet",
      protocol: "tcp",
      destinationPort: 23,
      eventType: "connection_closed",
      severity: "low",
    });
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Telnet honeypod listening on ${PORT}`);
});
