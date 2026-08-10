# Podmień starą linijkę 'FROM rust:1.80-slim' na:
FROM rust:1.85-slim as builder

WORKDIR /usr/src/app

# Kopiowanie zależności i kodu źródłowego
COPY . .

# Kompilacja wersji produkcyjnej
RUN cargo build --release

# Stage 2: Lekki obraz produkcyjny (Debian Slim)
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/klovy-chat-server /app/klovy-chat-server
COPY --from=builder /usr/src/app/target/release/migrate-message-content-seal /app/migrate-message-content-seal

EXPOSE 6701

CMD ["/app/klovy-chat-server"]