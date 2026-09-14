FROM rust:1-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --bin max_authorization_challenge


FROM debian:bookworm-slim

RUN useradd --create-home --uid 10001 challenge

WORKDIR /app

COPY --from=builder /build/target/release/max_authorization_challenge /usr/local/bin/max_authorization_challenge
COPY manifest.json manifest.challenge.maxsig trusted_admin_public.key ./

RUN mkdir -p /app/state \
    && chown challenge:challenge /app/state

USER challenge

ENV CHALLENGE_LISTEN_ADDR=0.0.0.0:8080

EXPOSE 8080

CMD ["max_authorization_challenge", "serve"]
