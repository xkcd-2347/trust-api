use actix_web::{Responder, web, error, http::StatusCode, HttpResponse, web::Json, web::ServiceConfig, post, get};
use core::str::FromStr;
use packageurl::PackageUrl;
use utoipa::ToSchema;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use serde_json::json;

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

#[utoipa::path(
    responses(
        (status = 200, description = "Package found", body = Package),
        (status = NOT_FOUND, description = "Package was not found", body = ApiError),
        (status = BAD_REQUEST, description = "Invalid package URL", body = ApiError),
        (status = BAD_REQUEST, description = "Missing query argument", body = ApiError)
    ),
    params(
        ("purl" = String, Query, description = "Package URL to query"),
    )
)]
#[get("/api/package")]
pub async fn get_package(query: web::Query<PackageQuery>) -> Result<HttpResponse, ApiError> {
    if let Some(purl) = &query.purl {
        if let Ok(purl) = PackageUrl::from_str(&purl) {
            let p = Package{
                purl: purl.to_string(),
                href: format!("/api/package?purl={}", &urlencoding::encode(&purl.to_string())),
                snyk: None,
                vulnerabilities: Vec::new(),
            };
            Ok(HttpResponse::Ok().json(p))
        } else {
            Err(ApiError::InvalidPackageUrl { purl: purl.to_string() })
        }
    } else {
        Err(ApiError::MissingQueryArgument)
    }
}

#[derive(ToSchema, Serialize, Deserialize)]
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
        (status = BAD_REQUEST, description = "Invalid package URLs"),
    ),
)]
#[post("/api/package")]
pub async fn query_package(body: Json<PackageList>) -> Result<HttpResponse, ApiError> {
    let mut packages: Vec<Option<Package>> = Vec::new();
    for purl in body.list().iter() {
        if let Ok(purl) = PackageUrl::from_str(purl) {
            let p = Package {
                purl: purl.to_string(),
                href: format!("/api/package?purl={}", &urlencoding::encode(&purl.to_string())),
                snyk: None,
                vulnerabilities: Vec::new(),
            };
            packages.push(Some(p));
        } else {
            return Err(ApiError::InvalidPackageUrl { purl: purl.to_string() })
        }
    }
    Ok(HttpResponse::Ok().json(packages))
}

#[utoipa::path(
    request_body = PackageList,
    responses(
        (status = 200, description = "Package found", body = PackageDependencies),
        (status = BAD_REQUEST, description = "Invalid package URL"),
    ),
)]
#[get("/api/package/dependencies")]
pub async fn query_package_dependencies(body: Json<PackageList>) -> Result<HttpResponse, ApiError> {
    let mut dependencies: PackageDependencies = PackageDependencies(Vec::new());
    for purl in body.list().iter() {
        if let Ok(purl) = PackageUrl::from_str(purl) {
        } else {
            return Err(ApiError::InvalidPackageUrl { purl: purl.to_string() })
        }
    }
    Ok(HttpResponse::Ok().json(dependencies))
}

#[utoipa::path(
    request_body = PackageList,
    responses(
        (status = 200, description = "Package found", body = PackageDependants),
        (status = BAD_REQUEST, description = "Invalid package URL"),
    ),
)]
#[get("/api/package/dependants")]
pub async fn query_package_dependants(body: Json<PackageList>)-> Result<HttpResponse, ApiError> {
    let mut dependants: PackageDependants = PackageDependants(Vec::new());
    for purl in body.list().iter() {
        if let Ok(purl) = PackageUrl::from_str(purl) {
        } else {
            return Err(ApiError::InvalidPackageUrl { purl: purl.to_string() })
        }
    }
    Ok(HttpResponse::Ok().json(dependants))
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct Package {
    purl: String,
    href: String,
    vulnerabilities: Vec<Vulnerability>,
    snyk: Option<SnykData>,
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct PackageRef {
    purl: String,
    href: String,
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct SnykData;

#[derive(ToSchema, Serialize, Deserialize)]
pub struct Vulnerability;

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
        }
    }
}
