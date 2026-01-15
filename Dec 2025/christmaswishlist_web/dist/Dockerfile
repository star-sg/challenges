FROM rust:1.83-slim as builder

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml ./

COPY src ./src
COPY static ./static

RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/templatesanta /app/
COPY --from=builder /usr/src/app/static /app/static

ENV FLAG="HEX{dummy_flag}"

RUN useradd -m -u 1000 santa && \
    chown -R santa:santa /app

USER santa

# change port
EXPOSE 8080 

CMD ["./christmaswishlist"]
