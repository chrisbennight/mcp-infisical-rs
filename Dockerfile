# syntax=docker/dockerfile:1.27@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e

ARG RUST_VERSION=1.96.1

FROM rust:${RUST_VERSION}-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3 AS builder
WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Embed the linked Rust dependency inventory so the runtime binary can be scanned.
ADD --checksum=sha256:42b66c852fbb9074a9ca356279a92eb753f48dde16017b8c82f48dcd05d6c856 \
    https://github.com/rust-secure-code/cargo-auditable/releases/download/v0.7.6/cargo-auditable-x86_64-unknown-linux-musl.tar.xz /tmp/cargo-auditable.tar.xz
RUN tar -xJf /tmp/cargo-auditable.tar.xz -C /tmp \
    && install -m 0755 /tmp/cargo-auditable-x86_64-unknown-linux-musl/cargo-auditable /usr/local/cargo/bin/cargo-auditable \
    && rm -rf /tmp/cargo-auditable.tar.xz /tmp/cargo-auditable-x86_64-unknown-linux-musl

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

# The digest-pinned image supplies the bootstrap compiler and system libraries.
# rust-toolchain.toml deliberately selects the effective build compiler; record
# it and fail if an environment override selects a different version.
RUN expected="$(sed -n 's/^channel = "\([0-9.]*\)"$/\1/p' rust-toolchain.toml)" \
    && test -n "$expected" \
    && test "$(rustc --version | cut -d ' ' -f 2)" = "$expected" \
    && rustc --version --verbose > /usr/local/share/mcp-rustc.txt

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
    cargo auditable build --release --locked --bin mcp-infisical-rs \
    && cp target/release/mcp-infisical-rs /usr/local/bin/mcp-infisical-rs

# Preserve the vetted GCC support library without shipping unused TLS libraries.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2 AS runtime-libraries

FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:89815d620ac01d8de13cdaf04d19ed874447ca2296d4985b14b818f6e5e47854 AS runtime
COPY --from=runtime-libraries /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
COPY --from=runtime-libraries /var/lib/dpkg/status.d/libgcc-s1 /var/lib/dpkg/status.d/libgcc-s1.md5sums /var/lib/dpkg/status.d/gcc-14-base /var/lib/dpkg/status.d/gcc-14-base.md5sums /var/lib/dpkg/status.d/
COPY --from=runtime-libraries /usr/share/doc/gcc-14-base/ /usr/share/doc/gcc-14-base/
COPY --from=builder /usr/local/bin/mcp-infisical-rs /mcp-infisical-rs
COPY --from=builder /usr/local/share/mcp-rustc.txt /usr/share/mcp-rustc.txt

COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/mcp-infisical-rs/
USER nonroot:nonroot
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["/mcp-infisical-rs", "--healthcheck"]

ENTRYPOINT ["/mcp-infisical-rs"]
