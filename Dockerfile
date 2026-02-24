FROM rust:1.84-slim-bullseye as builder

WORKDIR /usr/src/app

# Create a dummy project to cache dependencies
RUN cargo new --bin ai-agent-cleaner
WORKDIR /usr/src/app/ai-agent-cleaner

# Copy Cargo files
COPY Cargo.toml ./

# Build dependencies only
RUN cargo build --release
RUN rm src/*.rs

# Copy source code
COPY src ./src

# Build actual binary
RUN cargo build --release

# Runtime stage
FROM debian:bullseye-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /usr/src/app/ai-agent-cleaner/target/release/ai-agent-cleaner /usr/local/bin/ai-agent-cleaner

# Add user
RUN useradd -m -u 1000 lornu
USER lornu

ENTRYPOINT ["ai-agent-cleaner"]
