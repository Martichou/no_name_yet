#[macro_use]
extern crate error_chain;
extern crate hyper;

mod ssl_expire;

use hyper::Client;
use hyper_tls::HttpsConnector;
use serde::Deserialize;
use ssl_expire::SslExpiration;
use std::fs;
use url::Url;

#[derive(Debug, Deserialize)]
struct Server {
    host: String,
    fallback_ip: String,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let servers_json =
        fs::read_to_string("/Users/volt/Documents/Work/updown_clone/src/server.json")
            .expect("Unable to read file");
    let servers: Vec<Server> =
        serde_json::from_str(&servers_json).expect("JSON was not well-formatted");

    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    for x in servers {
        println!("{}", x.host);

        let url = Url::parse(&x.host)?;

        let expiration = SslExpiration::from_domain_name_with_port(url.host_str().expect("Failure in host_str"), x.port).unwrap();
        println!(" - SSL's expire in {} days", expiration.days());

        let resp = client.follow_redirects().get(x.host.parse()?).await?;
        println!(" - Response: {}", resp.status());

        println!("")
    }

    Ok(())
}
