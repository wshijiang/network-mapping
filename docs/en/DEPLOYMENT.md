# Server deployment

[Documentation](README.md) · [Full deployment reference (Chinese)](https://github.com/wshijiang/network-mapping/blob/main/docs/DEPLOYMENT.md)

## Components and prerequisites

Deploy PostgreSQL and Elasticsearch 9.5.x, then the Rust server with the built Web console, and finally register scanner nodes. Component versions are independent; confirm task/result and Worker compatibility before upgrading. Container deployment and systemd installation details remain in the [Chinese deployment reference](https://github.com/wshijiang/network-mapping/blob/main/docs/DEPLOYMENT.md) and [Docker guide](https://github.com/wshijiang/network-mapping/blob/main/docs/DOCKER.md).

Source builds require the Rust toolchain for edition 2024, PostgreSQL, trusted CA certificates, and the frontend build. Check the pinned Dockerfile/CI for native build dependencies.

```sh
# Server repository
git clone https://github.com/wshijiang/network-mapping.git
cd network-mapping
cargo build --locked --release
```

Build the frontend in its separate repository with `pnpm install --frozen-lockfile` and `pnpm build`. Set the server's `[frontend].directory` to the resulting `dist/` directory. The distribution must contain all four entries: `index.html`, `login.html`, `search.html` and `asset.html`, as well as their assets.

## Configure and start

Edit the complete repository `config.toml`; do not use a short documentation snippet as a full configuration. Set database and Elasticsearch connections, TLS paths, frontend paths, encryption key and scanner token pepper for the real environment. Relative frontend paths are resolved from the configuration file directory. Runtime policies already published to the database take priority over initialization values in files.

TLS is enabled by default. Provide a valid certificate chain and private key. If TLS is disabled, the listen address must be a loopback IP such as `127.0.0.1` or `::1`. A bridge-network port mapping cannot expose a container's loopback listener. Keep certificate validation enabled for Elasticsearch, external services and scanner connections.

```sh
./target/release/network_mapping_server --config config.toml
```

The first successful startup with an empty database creates an administrator and prints a random password. Store it securely, sign in and change it. Then create and register a scanner. Never commit credentials or deployment-specific configuration.

## Verification and upgrades

Check the real HTTPS sign-in page and representative authenticated APIs using a trusted CA. `GET`/`HEAD /healthz` returns 200 when PostgreSQL and Elasticsearch are ready, or 503 otherwise, with no dependency details in the response. A running process or open port alone is not proof of readiness.

Before upgrades, preserve PostgreSQL and Elasticsearch data and the existing `server.encrypt_key` and scanner pepper. Follow feature-specific migrations: transport-aware endpoint changes require the documented offline rebuild; notification queue changes require coordinated server replacement. Do not discard immutable observations, keys or node identities to force an upgrade.

See the [current service protocol and migration matrix](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md), [change log](https://github.com/wshijiang/network-mapping/blob/main/docs/CHANGELOG.md) and [complete deployment guide](https://github.com/wshijiang/network-mapping/blob/main/docs/DEPLOYMENT.md) before production rollout.

## Language support

The Web console detects the browser's first language, supports English and Simplified Chinese, and saves manual choices in a cookie. This does not change the business time zone or stored data. See [language rules and documentation builds](LOCALIZATION.md).
