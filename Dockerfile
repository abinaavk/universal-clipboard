FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY server ./server
COPY shared ./shared
COPY web ./web
ENV HOST=0.0.0.0 PORT=8787 UC_DATA_DIR=/data
VOLUME /data
EXPOSE 8787
USER node
CMD ["node", "server/server.js"]
