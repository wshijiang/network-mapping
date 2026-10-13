use clap::Parser;
use network_mapping_server::{application, config::Clis};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    application::run(Clis::parse()).await
}
