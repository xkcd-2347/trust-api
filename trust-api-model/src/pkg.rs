use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(Package {
purl: Some("pkg:maven/org.apache.quarkus/quarkus@1.2".to_string()),
href: Some(format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/org.apache.quarkus/quarkus@1.2"))),
trusted: Some(true),
trusted_versions: vec![PackageRef {
purl: "pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003".to_string(),
href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003")),
trusted: Some(true)
}],
vulnerabilities: vec![VulnerabilityRef {
cve: "CVE-1234".into(),
href: "/api/vulnerability/CVE-1234".into()
}],
snyk: None,
}))]
pub struct Package {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "trustedVersions")]
    pub trusted_versions: Vec<PackageRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<VulnerabilityRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snyk: Option<SnykData>,
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(VulnerabilityRef {
cve: "CVE-1234".into(),
href: "/api/vulnerability/CVE-1234".into()
}))]
pub struct VulnerabilityRef {
    pub cve: String,
    pub href: String,
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(PackageRef {
purl: "pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003".to_string(),
href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003")),
trusted: Some(true)
}))]
pub struct PackageRef {
    pub purl: String,
    pub href: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
pub struct SnykData;

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
pub struct PackageDependencies(pub Vec<PackageRef>);

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
pub struct PackageDependents(pub Vec<PackageRef>);

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = "[\"pkg:maven/org.quarkus/quarkus@1.2\"]")]
pub struct PackageList(pub Vec<String>);

impl PackageList {
    pub fn list(&self) -> &Vec<String> {
        &self.0
    }
}
