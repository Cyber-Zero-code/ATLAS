# Project ATLAS — Optional External Linux Security Execution Gateway
FROM node:22-bookworm-slim AS builder
WORKDIR /app
COPY package.json tsconfig.json ./
COPY src ./src
RUN npm install && npm run build

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    nmap \
    tshark \
    python3 \
    iproute2 \
    procps \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd -r atlasworker \
  && useradd -r -g atlasworker -u 10001 -d /home/atlasworker -s /usr/sbin/nologin atlasworker \
  && mkdir -p /tmp/atlas-worker-sandbox /app \
  && chown -R atlasworker:atlasworker /tmp/atlas-worker-sandbox /app

WORKDIR /app
COPY --from=builder --chown=atlasworker:atlasworker /app/dist ./dist
COPY --chown=atlasworker:atlasworker scripts ./scripts
COPY --chown=atlasworker:atlasworker package.json ./package.json

USER atlasworker
EXPOSE 8443

FROM node:20-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends nmap tshark ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

ENV NODE_ENV=production
EXPOSE 10000
CMD ["node", "dist/src/server.js"]



CMD ["node", "dist/src/server.js"]
