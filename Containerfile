FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

ADD /target/release/trust-api /
ENV RUST_LOG info

EXPOSE 8080

ENTRYPOINT ["/trust-api", "run", "-p", "8080"]
