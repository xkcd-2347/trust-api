use actix_web::web::Data;
use actix_web::{middleware::Logger, App, HttpServer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::package;
use crate::vulnerability;

pub struct Server {
    bind: String,
    port: u16,
    guac_url: String,
}

#[derive(OpenApi)]
#[openapi(
        paths(
            package::get_package,
            package::query_package,
            package::query_package_dependencies,
            package::query_package_dependants,
            package::query_package_versions,
            vulnerability::query_vulnerability,
        ),
        components(
            schemas(package::Package, package::PackageList, package::PackageDependencies, package::PackageDependants, package::PackageRef, package::SnykData, package::VulnerabilityRef, vulnerability::Vulnerability)
        ),
        tags(
            (name = "package", description = "Package query endpoints."),
            (name = "vulnerability", description = "Vulnerability query endpoints")
        ),
    )]
pub struct ApiDoc;

impl Server {
    pub fn new(bind: String, port: u16, guac_url: String) -> Self {
        Self {
            bind,
            port,
            guac_url,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let openapi = ApiDoc::openapi();

        HttpServer::new(move || {
            App::new()
                .wrap(Logger::default())
                .app_data(Data::new(package::TrustedContent::new(&self.guac_url)))
                .configure(package::configure())
                .configure(vulnerability::configure())
                .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", openapi.clone()))
        })
        .bind((self.bind, self.port))?
        .run()
        .await?;
        Ok(())
    }
}
