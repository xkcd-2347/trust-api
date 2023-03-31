use actix_web::{
    error, get, http::StatusCode, post, web, web::Json, web::ServiceConfig, HttpResponse, Responder,
};
use core::str::FromStr;
use guac::client::GuacClient;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use thiserror::Error;
use utoipa::ToSchema;

pub(crate) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(get_package);
        config.service(query_package);
        config.service(query_package_dependencies);
        config.service(query_package_dependants);
    }
}

#[derive(serde::Deserialize)]
pub struct PackageQuery {
    purl: Option<String>,
}

static TRUSTED_GAV: &str = include_str!("../data/trusted-gav.json");

pub struct TrustedContent {
    data: HashMap<String, String>,
    client: GuacClient,
}

impl TrustedContent {
    pub fn new(url: &str) -> Self {
        let mut data = HashMap::new();
        let input: serde_json::Value = serde_json::from_str(TRUSTED_GAV).unwrap();
        if let Some(input) = input.as_array() {
            for entry in input.iter() {
                let upstream = entry["upstream"].as_str().unwrap().to_string();
                let tc = entry["trusted"].as_str().unwrap().to_string();
                data.insert(upstream, tc);
            }
        }
        let client = GuacClient::new(url.to_string());

        Self { data, client }
    }

    // TODO: Use GUAC instead of the internal hashmap for package lookup
    fn get_trusted(&self, purl: &str) -> Result<Package, ApiError> {
        if let Ok(purl) = PackageUrl::from_str(&purl) {
            let query_purl = format!(
                "pkg:{}/{}/{}@{}",
                purl.ty(),
                purl.namespace().unwrap(),
                purl.name(),
                purl.version().unwrap()
            );
            let mut trusted_versions = Vec::new();
            if let Some(p) = self.data.get(&query_purl) {
                trusted_versions.push(PackageRef {
                    purl: p.clone(),
                    href: format!("/api/package?purl={}", &urlencoding::encode(&p)),
                });
            }
            let p = Package {
                purl: Some(purl.to_string()),
                href: Some(format!(
                    "/api/package?purl={}",
                    &urlencoding::encode(&purl.to_string())
                )),
                trusted_versions,
                snyk: None,
                vulnerabilities: Vec::new(),
            };
            Ok(p)
        } else {
            Err(ApiError::InvalidPackageUrl {
                purl: purl.to_string(),
            })
        }
    }

    async fn get_dependencies(&self, purl: &str) -> Result<PackageDependencies, ApiError> {
        let deps = self.client.get_dependencies(purl).await.map_err(|e| {
            log::warn!("Error getting dependencies from GUAC: {:?}", e);
            ApiError::InternalError
        })?;

        let mut ret = Vec::new();
        for dep in deps.iter() {
            let pkg = &dep.dependent_package;
            let t = &pkg.type_;
            for namespace in pkg.namespaces.iter() {
                for name in namespace.names.iter() {
                    for version in name.versions.iter() {
                        let purl = format!(
                            "pkg:{}/{}/{}@{}",
                            t, namespace.namespace, name.name, version.version
                        );
                        let p = PackageRef {
                            purl: purl.clone(),
                            href: format!("/api/package?purl={}", &urlencoding::encode(&purl)),
                        };
                        ret.push(p);
                    }
                }
            }
        }
        Ok(PackageDependencies(ret))
    }
}

#[utoipa::path(
    responses(
        (status = 200, description = "Package found", body = Package),
        (status = NOT_FOUND, description = "Package not found", body = Package, example = json!(Package {
            purl: None,
            href: None,
            trusted_versions: vec![PackageRef {
                purl: "pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003".to_string(),
                href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003")),
            }],
            vulnerabilities: Vec::new(),
            snyk: None,
        })),
        (status = BAD_REQUEST, description = "Invalid package URL"),
        (status = BAD_REQUEST, description = "Missing query argument")
    ),
    params(
        ("purl" = String, Query, description = "Package URL to query"),
    )
)]
#[get("/api/package")]
pub async fn get_package(
    data: web::Data<TrustedContent>,
    query: web::Query<PackageQuery>,
) -> Result<HttpResponse, ApiError> {
    if let Some(purl) = &query.purl {
        let p = data.get_trusted(purl)?;
        Ok(HttpResponse::Ok().json(p))
    } else {
        Err(ApiError::MissingQueryArgument)
    }
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
#[schema(example = "[\"pkg:maven/org.quarkus/quarkus@1.2\"]")]
pub struct PackageList(pub Vec<String>);

impl PackageList {
    pub fn list(&self) -> &Vec<String> {
        &self.0
    }
}

#[utoipa::path(
    request_body = PackageList,
    responses(
        (status = 200, description = "Package found", body = Vec<Option<Package>>),
        (status = NOT_FOUND, description = "Package not found", body = Package, example = json!(Package {
            purl: None,
            href: None,
            trusted_versions: vec![PackageRef {
                purl: "pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003".to_string(),
                href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003")),
            }],
            vulnerabilities: Vec::new(),
            snyk: None,
        })),
        (status = BAD_REQUEST, description = "Invalid package URLs"),
    ),
)]
#[post("/api/package")]
pub async fn query_package(
    data: web::Data<TrustedContent>,
    body: Json<PackageList>,
) -> Result<HttpResponse, ApiError> {
    let mut packages: Vec<Option<Package>> = Vec::new();
    for purl in body.list().iter() {
        if let Ok(p) = data.get_trusted(purl) {
            packages.push(Some(p));
        } else {
            packages.push(None);
        }
    }
    Ok(HttpResponse::Ok().json(packages))
}

#[utoipa::path(
    request_body = PackageList,
    responses(
        (status = 200, description = "Package found", body = Vec<PackageDependencies>),
        (status = BAD_REQUEST, description = "Invalid package URL"),
    ),
)]
#[post("/api/package/dependencies")]
pub async fn query_package_dependencies(
    data: web::Data<TrustedContent>,
    body: Json<PackageList>,
) -> Result<HttpResponse, ApiError> {
    let mut dependencies: Vec<PackageDependencies> = Vec::new();
    for purl in body.list().iter() {
        if let Ok(_) = PackageUrl::from_str(purl) {
            let lst = data.get_dependencies(purl).await?;
            dependencies.push(lst);
        } else {
            return Err(ApiError::InvalidPackageUrl {
                purl: purl.to_string(),
            });
        }
    }
    Ok(HttpResponse::Ok().json(dependencies))
}

#[utoipa::path(
    request_body = PackageList,
    responses(
        (status = 200, description = "Package found", body = Vec<PackageDependants>),
        (status = BAD_REQUEST, description = "Invalid package URL"),
    ),
)]
#[post("/api/package/dependants")]
pub async fn query_package_dependants(body: Json<PackageList>) -> Result<HttpResponse, ApiError> {
    let mut dependants: Vec<PackageDependants> = Vec::new();
    for purl in body.list().iter() {
        if let Ok(purl) = PackageUrl::from_str(purl) {
        } else {
            return Err(ApiError::InvalidPackageUrl {
                purl: purl.to_string(),
            });
        }
    }
    Ok(HttpResponse::Ok().json(dependants))
}

#[derive(ToSchema, Serialize, Deserialize)]
#[schema(example = json!(Package {
    purl: Some("pkg:maven/org.apache.quarkus/quarkus@1.2".to_string()),
    href: Some(format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/org.apache.quarkus/quarkus@1.2"))),
    trusted_versions: vec![PackageRef {
        purl: "pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003".to_string(),
        href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003")),
    }],
    vulnerabilities: vec![VulnerabilityRef {
        cve: "CVE-1234".into(),
        href: "/api/vulnerability/CVE-1234".into()
    }],
    snyk: None,
}))]
pub struct Package {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "trustedVersions")]
    pub trusted_versions: Vec<PackageRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<VulnerabilityRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snyk: Option<SnykData>,
}

#[derive(ToSchema, Serialize, Deserialize)]
#[schema(example = json!(VulnerabilityRef {
    cve: "CVE-1234".into(),
    href: "/api/vulnerability/CVE-1234".into()
}))]
pub struct VulnerabilityRef {
    cve: String,
    href: String,
}

#[derive(ToSchema, Serialize, Deserialize)]
#[schema(example = json!(PackageRef {
    purl: "pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003".to_string(),
    href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003")),
}))]
pub struct PackageRef {
    pub purl: String,
    pub href: String,
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct SnykData;

#[derive(ToSchema, Serialize, Deserialize)]
pub struct PackageDependencies(pub Vec<PackageRef>);

#[derive(ToSchema, Serialize, Deserialize)]
pub struct PackageDependants(pub Vec<PackageRef>);

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum ApiError {
    #[error("No query argument was specified")]
    MissingQueryArgument,
    #[error("Package {purl} was not found")]
    PackageNotFound { purl: String },
    #[error("{purl} is not a valid package URL")]
    InvalidPackageUrl { purl: String },
    #[error("Error processing error internally")]
    InternalError,
}

impl error::ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "status": self.status_code().as_u16(),
            "error": self.to_string(),
        }))
    }

    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::MissingQueryArgument => StatusCode::BAD_REQUEST,
            ApiError::PackageNotFound { purl } => StatusCode::NOT_FOUND,
            ApiError::InvalidPackageUrl { purl } => StatusCode::BAD_REQUEST,
            ApiError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
