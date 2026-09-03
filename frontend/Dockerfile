FROM node:26-alpine AS builder

WORKDIR /app
# Copy the manifest + lockfile first so the dependency layer is cached and
# `npm ci` installs the exact locked versions (reproducible builds).
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ── Production nginx stage ────────────────────────────────────────────────────
# nginx-unprivileged instead of the stock nginx image: the stock entrypoint
# starts as root to bind :80 and chown its cache dirs, so any RCE in the web
# tier lands as root inside the container. This variant runs as uid 101 for its
# whole lifetime and listens on 8080 (an unprivileged port) — see the matching
# `listen 8080` in nginx.conf and targetPort in k8s/frontend/deployment.yaml.
FROM nginxinc/nginx-unprivileged:1.31-alpine

# The COPYs need write access to paths owned by root in the base image.
USER root
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY security-headers.conf /etc/nginx/security-headers.conf

# Back to the unprivileged user for runtime. 101 is the `nginx` user in this
# image; the numeric form keeps runAsNonRoot admission checks happy.
USER 101

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
