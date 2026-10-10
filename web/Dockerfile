# Base images are pinned by the digest of their multi-arch index (docs/SUPPLY_CHAIN.md); the
# tag says what the digest was when it was pinned.
# node:24.21.0-alpine (Node 24 LTS; Node 20 reached its end of life in April 2026), pinned
# 2026-10-10. Build stage only: nothing of it is in the image that runs.
FROM node:25-alpine@sha256:bdf2cca6fe3dabd014ea60163eca3f0f7015fbd5c7ee1b0e9ccb4ced6eb02ef4 AS build
WORKDIR /web
COPY package.json package-lock.json ./
# npm ci installs exactly the lockfile and checks each package against its SHA-512 there.
# --ignore-scripts: no package runs an install script (esbuild's only checks its binary;
# esbuild, Vite's bundler Rolldown and its CSS minifier Lightning CSS take their binaries from
# per-platform packages in the lockfile, not from a download at install time).
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY tsconfig.json vite.config.ts index.html ./
COPY src ./src
COPY public ./public
RUN npm run build

# nginx:1.30.5-alpine (the stable branch; 1.27 has had no release since April 2025), pinned
# 2026-10-10. docker-compose.yml runs it as its unprivileged nginx user (101).
FROM nginx:1.30-alpine@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
