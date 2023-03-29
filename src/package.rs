use actix_web::{Responder, web, error, http::StatusCode, HttpResponse, web::ServiceConfig, get};
use core::str::FromStr;
use packageurl::PackageUrl;
use utoipa::ToSchema;
use serde::{Serialize, Deserialize};
use thiserror::Error;

pub(crate) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(get_package);
    }
}

#[derive(serde::Deserialize)]
pub struct PackageQuery {
    purl: Option<String>,
}

#[utoipa::path(
    responses(
        (status = 200, description = "Package found", body = Package),
        (status = NOT_FOUND, description = "Package was not found"),
        (status = BAD_REQUEST, description = "Invalid package URL"),
        (status = BAD_REQUEST, description = "Missing query argument")
    ),
    params(
        ("purl" = String, Query, description = "Package URL to query"),
    )
)]
#[get("/api/package")]
pub async fn get_package(query: web::Query<PackageQuery>) -> Result<HttpResponse, ApiError> {
    log::info!("Query {:?}", query.purl);
    if let Some(purl) = &query.purl {
        if let Ok(purl) = PackageUrl::from_str(&purl) {
            let p = Package{
                purl,
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
pub struct Package {
    purl: PackageUrl<'static>
}

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
