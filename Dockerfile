FROM rust:1.59.0 AS build
WORKDIR /usr/src

RUN rustup target add x86_64-unknown-linux-musl

RUN USER=root cargo new webdav-server
WORKDIR /usr/src/webdav-server
COPY ./ ./
RUN cargo install --target x86_64-unknown-linux-musl --path .

# Clean image for execution
FROM scratch

RUN mkdir -p /data
COPY webdav-server.toml /data/
RUN ln -s /usr/local/cargo/bin/webdav-server.toml /data/webdav-server.toml

COPY --from=build /usr/local/cargo/bin/webdav-server .
USER 1000
CMD ["./webdav-server"]