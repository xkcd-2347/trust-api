use actix_web::{Responder, HttpResponse, web::ServiceConfig, get};
use core::str::FromStr;
use packageurl::PackageUrl;
use utoipa::ToSchema;
use serde::{Serialize, Deserialize};

pub(crate) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(get_package);
    }
}

#[utoipa::path(
    responses(
        (status = 200, description = "Package found", body = Package),
        (status = NOT_FOUND, description = "Package was not found")
    ),
    params(
        ("purl" = String, Query, description = "Package URL to query"),
    )
)]
#[get("/api/package")]
pub async fn get_package(url: String) -> impl Responder {
    let p = Package{};
    HttpResponse::Ok().json(p)
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct Package {}
