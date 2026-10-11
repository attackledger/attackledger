# Base images are pinned by the digest of their multi-arch index (docs/SUPPLY_CHAIN.md); the
# tag says what the digest was when it was pinned.
# node:24.21.0-alpine (Node 24 LTS; Node 20 reached its end of life in April 2026), pinned
# 2026-10-10. Build stage only: nothing of it is in the image that runs.
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
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
# Alpine fixes published after that build, for the HIGH findings of tools/scan_images.sh
# (2026-10-11; docs/SUPPLY_CHAIN.md, "OS packages"). Each is a floor, not an exact version: the
# build fails if the mirror lacks at least that version, and does not break when a newer one
# replaces it. Remove a package from the list once the pinned base image has that version.
#   zlib CVE-2026-85091, pcre2 CVE-2026-103111, libexpat CVE-2026-93990, tiff CVE-2026-4775;
#   OpenSSL 3.5.9 (libssl3, libcrypto3) for the four 3.5.8 advisories the scanner matches by
#   version, without an Alpine record (CVE-2026-54873, -72897, -84782, -84784).
RUN apk add --no-cache 'zlib>=1.3.2-r1' 'pcre2>=10.49-r0' 'libexpat>=2.8.5-r0' 'tiff>=4.7.2-r0' \
      'libssl3>=3.5.9-r0' 'libcrypto3>=3.5.9-r0'
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
