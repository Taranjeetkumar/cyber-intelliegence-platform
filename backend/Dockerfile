FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache nmap nmap-nselibs nmap-scripts

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 5000

CMD ["npm", "start"]
