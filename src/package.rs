use crate::guac::Guac;
use actix_web::{
    error, get, http::StatusCode, post, web, web::Json, web::ServiceConfig, HttpResponse,
};
use core::str::FromStr;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use utoipa::ToSchema;

pub(crate) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(get_package);
        config.service(query_package);
        config.service(query_package_dependencies);
        config.service(query_package_dependants);
        config.service(get_trusted);
        config.service(query_package_versions);
    }
}

#[derive(serde::Deserialize)]
pub struct PackageQuery {
    purl: Option<String>,
}

static TRUSTED_GAV: &str = include_str!("../data/trusted-gav.json");

pub struct TrustedContent {
    data: HashMap<String, String>,
    client: Arc<Guac>,
}

impl TrustedContent {
    pub fn new(client: Arc<Guac>) -> Self {
        let mut data = HashMap::new();
        let input: serde_json::Value = serde_json::from_str(TRUSTED_GAV).unwrap();
        if let Some(input) = input.as_array() {
            for entry in input.iter() {
                let upstream = entry["upstream"].as_str().unwrap().to_string();
                let tc = entry["trusted"].as_str().unwrap().to_string();
                data.insert(upstream, tc);
            }
        }
        Self { data, client }
    }

    pub async fn get_versions(&self, purl_str: &str) -> Result<Vec<PackageRef>, ApiError> {
        if let Ok(purl) = PackageUrl::from_str(purl_str) {
            //get related packages from guac
            let mut trusted_versions: Vec<PackageRef> =
                self.client.get_packages(purl.clone()).await.map_err(|_| ApiError::InternalError)?;

            for (key, value) in self.data.iter() {
                if let Ok(p) = PackageUrl::from_str(key) {
                    if p.name() == purl.name() {
                        trusted_versions.push(PackageRef {
                            purl: value.clone(),
                            href: format!("/api/package?purl={}", &urlencoding::encode(value)),
                            trusted: Some(true),
                        });
                    }
                }
            }

            Ok(trusted_versions)
        } else {
            Err(ApiError::InvalidPackageUrl {
                purl: purl_str.to_string(),
            })
        }
    }

    async fn get_trusted(&self, purl_str: &str) -> Result<Package, ApiError> {
        if let Ok(purl) = PackageUrl::from_str(purl_str) {
            let vulns = self.client.get_vulnerabilities(purl_str).await.map_err(|_| ApiError::InternalError)?;

            //get related packages from guac
            let mut trusted_versions: Vec<PackageRef> =
                self.client.get_packages(purl.clone()).await.map_err(|_| ApiError::InternalError)?;

            //get trusted gav versions
            if purl.version().is_some() && purl.namespace().is_some() {
                let query_purl = format!(
                    "pkg:{}/{}/{}@{}",
                    purl.ty(),
                    purl.namespace().unwrap(),
                    purl.name(),
                    purl.version().unwrap()
                );
                if let Some(p) = self.data.get(&query_purl) {
                    trusted_versions.push(PackageRef {
                        purl: p.clone(),
                        href: format!("/api/package?purl={}", &urlencoding::encode(p)),
                        trusted: Some(true),
                    });
                }
            }

            let p = Package {
                purl: Some(purl.to_string()),
                href: Some(format!(
                    "/api/package?purl={}",
                    &urlencoding::encode(&purl.to_string())
                )),
                trusted: Some(self.is_trusted(purl.clone())),
                trusted_versions,
                snyk: None,
                vulnerabilities: vulns,
            };
            Ok(p)
        } else {
            Err(ApiError::InvalidPackageUrl {
                purl: purl_str.to_string(),
            })
        }
    }

    // temp fn to decide if the package is trusted based on its version or namespace
    fn is_trusted(&self, purl: PackageUrl<'_>) -> bool {
        purl.version().map_or(false, |v| v.contains("redhat"))
            || purl.namespace().map_or(false, |v| v == "redhat")
    }

    async fn get_all_trusted(&self) -> Result<Vec<Package>, ApiError> {
        let mut trusted_versions = Vec::new();
        for (k, v) in &self.data {
            trusted_versions.push(Package {
                purl: Some(k.clone()),
                href: None,
                trusted: Some(false),
                trusted_versions: vec![PackageRef {
                    purl: v.clone(),
                    href: format!("/api/package?purl={}", &urlencoding::encode(&v.to_string())),
                    trusted: Some(true),
                }],
                vulnerabilities: vec![],
                snyk: None,
            });
        }

        trusted_versions.extend(
            self.client
                .get_all_packages()
                .await
                .map_err(|_| ApiError::InternalError)?,
        );
        Ok(trusted_versions)
    }
}

#[utoipa::path(
    responses(
        (status = 200, description = "Package found", body = Package),
        (status = NOT_FOUND, description = "Package not found", body = Package, example = json!(Package {
            purl: None,
            href: None,
            trusted: None,
            trusted_versions: vec![PackageRef {
                purl: "pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003".to_string(),
                href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003")),
                trusted: None,
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
        let p = data.get_trusted(purl).await?;
        Ok(HttpResponse::Ok().json(p))
    } else {
        Err(ApiError::MissingQueryArgument)
    }
}

#[utoipa::path(
    responses(
        (status = 200, description = "Get the entire inventory", body = Vec<Package>),
    )
)]
#[get("/api/trusted")]
pub async fn get_trusted(data: web::Data<TrustedContent>) -> Result<HttpResponse, ApiError> {
    Ok(HttpResponse::Ok().json(data.get_all_trusted().await?))
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
            trusted: None,
            trusted_versions: vec![PackageRef {
                purl: "pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003".to_string(),
                href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003")),
                trusted: None,
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
        if let Ok(p) = data.get_trusted(purl).await {
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
    data: web::Data<Guac>,
    body: Json<PackageList>,
) -> Result<HttpResponse, ApiError> {
    let mut dependencies: Vec<PackageDependencies> = Vec::new();
    for purl in body.list().iter() {
        if PackageUrl::from_str(purl).is_ok() {
            let lst = data.get_dependencies(purl).await.map_err(|_| ApiError::InternalError)?;
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
pub async fn query_package_dependants(
    data: web::Data<Guac>,
    body: Json<PackageList>,
) -> Result<HttpResponse, ApiError> {
    let mut dependencies: Vec<PackageDependencies> = Vec::new();
    for purl in body.list().iter() {
        if PackageUrl::from_str(purl).is_ok() {
            let lst = data.get_dependants(purl).await.map_err(|_| ApiError::InternalError)?;
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
        (status = 200, description = "Package found", body = Vec<PackageRef>),
        (status = BAD_REQUEST, description = "Invalid package URL"),
    ),
)]
#[post("/api/package/versions")]
pub async fn query_package_versions(
    data: web::Data<TrustedContent>,
    body: Json<PackageList>,
) -> Result<HttpResponse, ApiError> {
    let mut versions = Vec::new();
    for purl_str in body.list().iter() {
        if PackageUrl::from_str(purl_str).is_ok() {
            versions = data.get_versions(purl_str).await?;
        } else {
            return Err(ApiError::InvalidPackageUrl {
                purl: purl_str.to_string(),
            });
        }
    }
    Ok(HttpResponse::Ok().json(versions))
}

#[derive(ToSchema, Serialize, Deserialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "trustedVersions")]
    pub trusted_versions: Vec<PackageRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<VulnerabilityRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snyk: Option<SnykData>,
}

#[derive(ToSchema, Serialize, Deserialize, PartialEq)]
#[schema(example = json!(VulnerabilityRef {
    cve: "CVE-1234".into(),
    href: "/api/vulnerability/CVE-1234".into()
}))]
pub struct VulnerabilityRef {
    pub cve: String,
    pub href: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
#[schema(example = json!(PackageRef {
    purl: "pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003".to_string(),
    href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/org.apache.quarkus/quarkus@1.2-redhat-003")),
    trusted: Some(true)
}))]
pub struct PackageRef {
    pub purl: String,
    pub href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
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
            ApiError::PackageNotFound { purl: _ } => StatusCode::NOT_FOUND,
            ApiError::InvalidPackageUrl { purl: _ } => StatusCode::BAD_REQUEST,
            ApiError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
