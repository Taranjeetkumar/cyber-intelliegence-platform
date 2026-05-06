FROM node:20-alpine

WORKDIR /app

COPY base ./base
COPY telnet/server.js .

EXPOSE 2323

CMD ["node", "server.js"]
