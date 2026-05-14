FROM node:20-alpine

WORKDIR /app

COPY base ./base
COPY ssh/server.js .

EXPOSE 2222

CMD ["node", "server.js"]
