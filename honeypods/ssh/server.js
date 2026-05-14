const { generateKeyPairSync } = require("crypto");
const { Server } = require("ssh2");
const { emitEvent, normalizeIp } = require("./base/emitEvent");

const PORT = Number(process.env.PORT || 2222);
const hostKey = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "pkcs1", format: "pem" },
}).privateKey;

const server = new Server(
  {
    hostKeys: [hostKey],
    ident: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
  },
  (client) => {
    const sourceIp = normalizeIp(client._sock?.remoteAddress);
    let attempts = 0;

    emitEvent({
      sourceIp,
      service: "ssh",
      protocol: "tcp",
      destinationPort: PORT,
      eventType: "connection_opened",
      severity: "low",
    });

    client.on("authentication", (ctx) => {
      attempts += 1;
      const password = ctx.method === "password" ? ctx.password : "";

      emitEvent({
        sourceIp,
        service: "ssh",
        protocol: "tcp",
        destinationPort: PORT,
        eventType: ctx.method === "password" ? "credential_attempt" : "auth_attempt",
        username: ctx.username,
        password,
        payload: `method=${ctx.method}; attempt=${attempts}`,
        severity: ctx.method === "password" ? "high" : "medium",
      });

      ctx.reject(["password"]);
    });

    client.on("error", (err) => {
      emitEvent({
        sourceIp,
        service: "ssh",
        protocol: "tcp",
        destinationPort: PORT,
        eventType: "client_error",
        payload: err.message,
        severity: "low",
      });
    });

    client.on("end", () => {
      if (attempts === 0) {
        emitEvent({
          sourceIp,
          service: "ssh",
          protocol: "tcp",
          destinationPort: PORT,
          eventType: "connection_closed_no_auth",
          severity: "low",
        });
      }
    });
  }
);

server.listen(PORT, "0.0.0.0", () => {
  console.log(`SSH honeypod listening on ${PORT}`);
});
