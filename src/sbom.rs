use std::collections::HashMap;

const REGISTRY: &[(&'static str, &'static str)] = &[(
    "pkg:maven/io.seedwing/seedwing-java-example@1.0.0-SNAPSHOT?type=jar",
    include_str!("../data/files/java-sbom.json"),

),
(
    "pkg:oci/ubi9@sha256:d03c30dddefc59229303f49a94105d537ac324c86df9177ec5be37d30d44672d?arch=x86_64&repository_url=registry.redhat.io/ubi9",
    include_str!("../data/files/ubi9-fake-sbom.json"),
)
];

#[derive(Clone)]
pub struct SbomRegistry {
    data: HashMap<String, serde_json::Value>,
}

impl SbomRegistry {
    pub fn new() -> Self {
        let mut data = HashMap::new();

        for entry in REGISTRY {
            data.insert(entry.0.to_string(), serde_json::from_str(entry.1).unwrap());
        }

        Self { data }
    }

    pub fn lookup(&self, purl: &str) -> Option<serde_json::Value> {
        self.data.get(purl).cloned()
    }
}
