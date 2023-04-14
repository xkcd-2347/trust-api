FROM registry.access.redhat.com/ubi9/ubi-minimal:latest as builder

ARG tag

RUN microdnf install -y gcc openssl  openssl-devel
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
ENV PATH "$PATH:/root/.cargo/bin"
LABEL org.opencontainers.image.source="https://github.com/xkcd-2347/trust-api"

RUN mkdir /usr/src/project
COPY . /usr/src/project
WORKDIR /usr/src/project

RUN TAG=$tag cargo build --release


FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

LABEL org.opencontainers.image.source="https://github.com/xkcd-2347/trust-api"

COPY --from=builder /usr/src/project/target/release/trust-api /

ENV RUST_LOG info
EXPOSE 8080
EXPOSE 8081

ENTRYPOINT ["/trust-api"]
