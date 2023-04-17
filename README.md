# trust-api

API server for trusted content (TC).

## Running on OpenShift

To run the service on OpenShift with test-data:

```
oc new-project trusted
oc apply -f k8s/guac
oc apply -f k8s/api
```

To query the API:

```
HOST=$(oc get route api -o jsonpath='{.spec.host}')
curl https://$HOST/api/trusted
```

## Running locally

Running:

``` 4d
cargo run -- run -p 8080
```

Usage:

``` 4d
curl --json '["pkg:maven/org.quarkus/quarkus@1.2"]' http://localhost:8080/api/package
```

## Testing with guac

Start guac:

``` 4d
podman run -p 8080:8080 -ti ghcr.io/xkcd-2347/guac:latest gql-server --gql-debug
```

Ingest test SBOMs:

```
podman run --net=host -v $PWD/data/files:/data:z -ti ghcr.io/xkcd-2347/guac:latest files /data
```

Run certifier:

```
 podman run --net=host -ti ghcr.io/xkcd-2347/guac:latest certifier
 ```

Run the API server:

```
cargo run -- run -p 8081
```

You can also run the API server using a container:

```
podman run -p 8080:8080 -ti ghcr.io/xkcd-2347/trust-api:latest run -p 8081 
```

### Example usages

```
curl --json '["pkg:maven/io.quarkus/quarkus-vertx@2.13.7.Final"]' http://localhost:8081/api/package | jq
```

```
curl --json '["pkg:maven/io.vertx/vertx-web@4.3.7"]' http://localhost:8081/api/package/dependents | jq
```

```
curl --json '["pkg:maven/io.vertx/vertx-web@4.3.7"]' http://localhost:8081/api/package/dependencies | jq
```

```
curl --json '["pkg:maven/io.vertx/vertx-web@4.3.7"]' http://localhost:8081/api/package/versions | jq
```
