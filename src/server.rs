use std::{
    error::Error,
    future::{self, Ready},
    net::Ipv4Addr,
};

use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    middleware::Logger,
    web::Data,
    web,
    App, HttpResponse, HttpServer,
};
use utoipa::{
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

use crate::package;
use crate::vulnerability;

pub struct Server {
    bind: String,
    port: u16,
}


#[derive(OpenApi)]
    #[openapi(
        paths(
            package::get_package,
            package::query_package,
            package::query_package_dependencies,
            package::query_package_dependants,
            vulnerability::query_vulnerability,
        ),
        components(
            schemas(package::Package, package::PackageList, package::PackageDependencies, package::PackageDependants, package::PackageRef, package::SnykData, package::Vulnerability)
        ),
        tags(
            (name = "package", description = "Package query endpoints."),
            (name = "vulnerability", description = "Vulnerability query endpoints")
        ),
    )]
pub struct ApiDoc;

impl Server {
    pub fn new(bind: String, port: u16) -> Self {
        Self { bind, port }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let openapi = ApiDoc::openapi();

        HttpServer::new(move || {
            App::new()
                .wrap(Logger::default())
                .configure(package::configure())
                .configure(vulnerability::configure())
                .service(
                    SwaggerUi::new("/swagger-ui/{_:.*}")
                        .url("/openapi.json", openapi.clone()),
                )
        })
        .bind((self.bind, self.port))?
        .run()
        .await?;
        Ok(())
    }
}
