# syntax=docker/dockerfile:1
# Supply the separately checked-out frontend as --build-context frontend=PATH.
FROM node:24.16.0-bookworm-slim@sha256:2c87ef9bd3c6a3bd4b472b4bec2ce9d16354b0c574f736c476489d09f560a203 AS frontend-builder
WORKDIR /frontend
RUN npm install --global pnpm@11.9.0
COPY --from=frontend package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
RUN pnpm install --frozen-lockfile
COPY --from=frontend src ./src
COPY --from=frontend public ./public
COPY --from=frontend LICENSE ./LICENSE
COPY --from=frontend index.html login.html search.html asset.html vite.config.js jsconfig.json tailwindcss.config.js ./
RUN node --test src/utils/*.test.js && pnpm test:targets && pnpm build
RUN test -f dist/index.html && test -f dist/login.html && test -f dist/search.html && test -f dist/asset.html && test -d dist/assets

FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS rust-builder
WORKDIR /build
ENV CARGO_BUILD_JOBS=2
RUN rustup component add rustfmt clippy
RUN apt-get update && apt-get install -y --no-install-recommends cmake libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && printf 'fn main() {}\n' > src/main.rs && cargo fetch --locked
COPY src ./src
COPY docker/config.example.toml ./config.toml

COPY source/database ./source/database
COPY source/open_source_projects.json ./source/open_source_projects.json
COPY templates ./templates
COPY assets/fonts ./assets/fonts

# Keep dependency downloads in cached build layers. Cache mounts alone are not
# persisted by cache-to=gha; correctness never depends on a warm cache.
RUN cargo fmt --check
RUN cargo clippy --locked --all-targets
RUN cargo test --locked -- --test-threads=4
RUN cargo build --locked --release && mkdir /out && install -m 0755 target/release/network_mapping_server /out/network_mapping_server

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 curl && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 network-mapping && useradd --uid 10001 --gid 10001 --no-create-home network-mapping \
    && install -d -o 10001 -g 10001 /var/lib/network-mapping /var/lib/network-mapping/maxmind /var/lib/network-mapping/scanner-diagnostics /var/log/network-mapping
WORKDIR /opt/network-mapping
COPY --from=rust-builder /out/network_mapping_server ./bin/network_mapping_server
COPY --from=frontend-builder /frontend/dist ./frontend/dist
COPY source/database ./source/database
COPY source/open_source_projects.json ./source/open_source_projects.json
COPY templates ./templates
COPY LICENSE ./licenses/LICENSE
COPY assets/fonts/Noto-LICENSE.txt assets/fonts/Apache-2.0.txt ./licenses/
COPY --from=frontend-builder /frontend/LICENSE ./licenses/frontend-LICENSE
ARG VERSION=development
ARG REVISION=unknown
ARG FRONTEND_REVISION=unknown
ARG FRONTEND_VERSION=unknown
ARG TARGETARCH
LABEL org.opencontainers.image.title="network-mapping-server" \
      org.opencontainers.image.source="https://github.com/wshijiang/network-mapping" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$REVISION \
      io.network-mapping.frontend.revision=$FRONTEND_REVISION \
      io.network-mapping.frontend.version=$FRONTEND_VERSION
RUN printf 'server-version=%s\nserver-commit=%s\nfrontend-version=%s\nfrontend-commit=%s\narchitecture=%s\nrust=1.98.0\nnode=24.16.0\npnpm=11.9.0\n' "$VERSION" "$REVISION" "$FRONTEND_VERSION" "$FRONTEND_REVISION" "$TARGETARCH" > BUILD-INFO
USER 10001:10001
EXPOSE 9999
ENV SERVER_TLS_NAME=localhost
# This checks HTTPS/frontend liveness, not ongoing PG/ES readiness.
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 CMD curl --fail --silent --show-error --cacert /etc/network-mapping/tls/ca.pem --resolve "$SERVER_TLS_NAME:9999:127.0.0.1" "https://$SERVER_TLS_NAME:9999/login" > /dev/null || exit 1
ENTRYPOINT ["/opt/network-mapping/bin/network_mapping_server"]
CMD ["--config", "/etc/network-mapping/config.toml"]
