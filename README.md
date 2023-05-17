# trust-api

API server for trusted content (TC).

## Running on OpenShift

See [this repository](https://github.com/xkcd-2347/trust-k8s)

## Running locally

Running:

```shell
cargo run -- run -p 8080
```

Usage:

```shell
curl --json '["pkg:maven/org.quarkus/quarkus@1.2"]' http://localhost:8080/api/package
```

## Testing with guac

Start guac:

```shell
podman run -p 8080:8080 -ti ghcr.io/xkcd-2347/guac:latest gql-server --gql-debug
```

Ingest test SBOMs:

```shell
podman run --net=host -v $PWD/data/files:/data:Z --rm -ti ghcr.io/xkcd-2347/guac:latest files /data
```

Run certifier:

```shell
podman run --net=host --rm -ti ghcr.io/xkcd-2347/guac:latest osv -p=false
 ```

Run the API server:

```shell
cargo run -- run -p 8081
```

You can also run the API server using a container:

```shell
podman run --net=host -ti ghcr.io/xkcd-2347/trust-api:latest run -p 8081
```

### Using Snyk

If `snyk-org` and `snyk-token` parameters are provided, the `api/package` call will check purl vulnerabilities in Snyk (on top of Guac).

```shell
cargo run -- run -p 8080 --snyk-org=63884128-5f57-4752-b9c0-9d0882873bf4 --snyk-token=<TOKEN>
```

### Example usages

### UBI Examples

```shell
curl --json '["pkg:oci/registry.redhat.io/ubi9@sha256:cb303404e576ff5528d4f08b12ad85fab8f61fa9e5dba67b37b119db24865df3"]' http://localhost:8081/api/package/dependencies | jq
```

```shell
curl --json '["pkg:rpm/redhat/openssl@1.1.1k-7.el8_6?arch=x86_64&epoch=1"]' http://localhost:8081/api/package | jq
```

```shell
curl -s "http://localhost:8081/api/vulnerability?cve=cve-2023-0286" | jq
```

#### Quarkus Examples

```shell
curl --json '["pkg:maven/io.quarkus/quarkus-vertx@2.16.2.Final?type=jar"]' http://localhost:8081/api/package | jq
```

```shell
curl --json '["pkg:maven/io.vertx/vertx-web@4.3.7"]' http://localhost:8081/api/package/dependents | jq
```

```shell
curl --json '["pkg:maven/io.vertx/vertx-web@4.3.7"]' http://localhost:8081/api/package/dependencies | jq
```

```shell
curl --json '["pkg:maven/io.vertx/vertx-web"]' http://localhost:8081/api/package/search | jq
```
