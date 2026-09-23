# syntax=docker/dockerfile:1

# Keep the Rust patch release explicit so local and CI runs use the same compiler.
# rust-toolchain.toml pins the same version for rustup and GitHub Actions.
FROM rust:1.96.0-bookworm

RUN rustup component add rustfmt clippy
RUN useradd --create-home --uid 10001 walden

ENV CARGO_HOME=/home/walden/.cargo
WORKDIR /workspace
RUN chown walden:walden /workspace

# Cache downloaded crates until the dependency manifests change.
COPY --chown=walden:walden Cargo.toml Cargo.lock ./
USER walden
RUN cargo fetch --locked

COPY --chown=walden:walden . .

CMD ["./scripts/check.sh"]
