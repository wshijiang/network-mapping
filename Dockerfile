# syntax=docker/dockerfile:1
# Supply the separately checked-out frontend as --build-context frontend=PATH.
FROM node:26.11.1-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567 AS frontend-builder
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

FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS rust-chef
WORKDIR /build
RUN rustup component add rustfmt clippy
RUN apt-get update && apt-get install -y --no-install-recommends cmake libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
RUN cargo install --locked --version 0.1.78 cargo-chef

FROM rust-chef AS rust-planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY build.rs ./
RUN cargo chef prepare --recipe-path recipe.json

FROM rust-chef AS rust-dependencies
COPY --from=rust-planner /build/recipe.json ./recipe.json
# Ordinary layers persist in the GHA mode=max cache, including compiled dependencies.
# Match each validation/build command so both test and release dependencies are warm.
RUN cargo chef cook --locked --clippy --all-targets --recipe-path recipe.json
RUN cargo chef cook --locked --all-targets --recipe-path recipe.json
RUN cargo chef cook --locked --release --recipe-path recipe.json

FROM rust-dependencies AS rust-builder
# Restore the real manifests and build script after cargo-chef's dummy project.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY build.rs ./
ENV NM_PUBLIC_CONFIG_FIELDS_FILE=src/public_config_fields.txt
COPY docker/config.example.toml ./config.toml
COPY docker/config.example.toml ./docker/config.example.toml

COPY source/database ./source/database
COPY source/open_source_projects.json ./source/open_source_projects.json
COPY templates ./templates
COPY assets/fonts ./assets/fonts

# Always validate the real sources; correctness never depends on a warm cache.
RUN cargo fmt --check
RUN cargo clippy --locked --all-targets
RUN cargo test --locked
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
