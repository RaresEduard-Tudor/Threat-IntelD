# ── build stage ─────────────────────────────────────────────────────────────
FROM node:20.19-alpine3.21 AS builder

WORKDIR /app

RUN corepack enable && corepack prepare yarn@stable --activate

COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile

COPY . .
RUN yarn build

# ── serve stage ──────────────────────────────────────────────────────────────
FROM nginx:1.27.5-alpine3.21

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO /dev/null http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
