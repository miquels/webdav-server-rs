FROM rust:1.59.0-alpine AS build
WORKDIR /usr/src

RUN rustup target add x86_64-unknown-linux-musl

RUN apk add linux-pam-dev rpcgen musl-dev libtirpc-dev 
RUN USER=root cargo new webdav-server
WORKDIR /usr/src/webdav-server
COPY ./ ./
RUN cargo install --target x86_64-unknown-linux-musl --path .

# Clean image for execution
FROM busybox:musl 

RUN mkdir -p /data
COPY webdav-server.toml /data/
RUN ln -s /data/webdav-server.toml ./webdav-server.toml

COPY --from=build /usr/local/cargo/bin/webdav-server .
USER 1000
CMD ["./webdav-server"]