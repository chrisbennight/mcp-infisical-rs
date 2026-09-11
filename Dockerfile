# syntax=docker/dockerfile:1.27@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e

ARG RUST_VERSION=1.96.1

FROM rust:${RUST_VERSION}-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3 AS builder
WORKDIR /build

# Where crates come from. This stage reaches the network, and the fleet wants
# that traffic through its caching proxy - but Docker gives a RUN step an
# environment built from this file rather than the caller's, so the address has
# to arrive as a build argument.
#
# Cargo reads no environment variable for a mirror, so unlike pip or npm it
# cannot simply be told: the redirect has to be a config file, appended from
# this value below. The name stays outside cargo's own CARGO_ namespace on
# purpose - cargo maps CARGO_REGISTRY_INDEX onto its removed registry.index key
# and aborts every invocation, and an ARG is visible to RUN as an environment
# variable, so that spelling would break the build it was meant to route.
#
# Left unsupplied it stays unset, no source is pinned, and cargo resolves from
# crates.io. That fallback is what keeps this image buildable away from the
# network the proxy lives on.
ARG CRATES_INDEX_URL

COPY . .

# Source replacement rather than an additional registry: it redirects the
# existing crates.io source instead of introducing a second one, so Cargo.lock
# goes on naming crates-io and a lock produced here still resolves from the
# public index.
#
# Appended rather than written, so whatever else .cargo/config.toml carries is
# preserved. The repository's copy deliberately no longer pins a source: a
# committed mirror address would be a hard dependency on a host that resolves
# only on the LAN, which is exactly what this argument exists to avoid.
RUN if [ -n "${CRATES_INDEX_URL}" ]; then \
      mkdir -p .cargo && \
      printf '\n[source.crates-io]\nreplace-with = "mirror"\n\n[source.mirror]\nregistry = "%s"\n' \
        "${CRATES_INDEX_URL}" >> .cargo/config.toml; \
    fi
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked --bin mcp-infisical-rs \
    && cp target/release/mcp-infisical-rs /usr/local/bin/mcp-infisical-rs

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
COPY --from=builder /usr/local/bin/mcp-infisical-rs /mcp-infisical-rs

COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/mcp-infisical-rs/
USER nonroot:nonroot
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["/mcp-infisical-rs", "--healthcheck"]

ENTRYPOINT ["/mcp-infisical-rs"]
