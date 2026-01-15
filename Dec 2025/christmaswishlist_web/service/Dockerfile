FROM rust:1.83-slim as builder

WORKDIR /usr/src/app

# Install dependencies
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

ENV FLAG="HEX{s4nt4s_m4g1c_t3mpl4t3_l34k5_s3cr3ts}"

RUN useradd -m -u 1000 santa && \
    chown -R santa:santa /app

USER santa

EXPOSE 8080

CMD ["./christmaswishlist"]
