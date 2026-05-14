FROM node:20-alpine

WORKDIR /app

COPY base ./base
COPY http/server.js .

EXPOSE 8080

CMD ["node", "server.js"]
