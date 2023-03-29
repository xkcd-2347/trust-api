# trust-api

API server for trusted content (TC).

Running:

``` 4d
cargo run -- run -p 8080
```

Usage:

``` 4d
curl --json '["pkg:maven/org.quarkus/quarkus@1.2"]' http://localhost:8080/api/package
```
