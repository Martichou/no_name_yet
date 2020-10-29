#[macro_use]
extern crate error_chain;

mod ssl_expire;

use serde::Deserialize;
use ssl_expire::SslExpiration;
use std::fs;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Debug, Deserialize)]
struct Server<'a> {
    host: &'a str,
    fallback_ip: &'a str,
    trust_cert: bool,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    env_logger::init();

    let servers_json =
        fs::read_to_string("/Users/volt/Documents/Work/updown_clone/src/server.json")
            .expect("Unable to read file");
    let servers: Vec<Server> =
        serde_json::from_str(&servers_json).expect("JSON was not well-formatted");

    for x in servers {
        println!("{}", x.host);

        let mut url = Url::parse(&x.host)?;
        url.set_port(Some(x.port)).map_err(|_| "cannot be base")?;

        {
            // Check for the SSL Certs expiration
            let host_str = url.host_str().expect("Failure in host_str");
            let expiration = SslExpiration::from_domain_name_with_port(host_str, x.port);
            match expiration {
                Ok(val) => println!(" - SSL's expire in {} days", val.days()),
                Err(_) => {
                    let expiration =
                        SslExpiration::from_domain_name_with_port(&x.fallback_ip, x.port);
                    match expiration {
                        Ok(val) => println!(" - SSL's expire in {} days", val.days()),
                        Err(err) => println!(" - SSL check failed due to : {}", err),
                    }
                }
            }
        }

        {
            // Check for the Status Code of the endpoint
            let scheme = url.scheme();
            // Dispatch to the correct check
            // Support for :
            // - https/http
            // - icmp (?)
            // - tcp (?)
            // - udp (?)
            // - ssh (?)
            // - ftp/sftp (?)
            if scheme.contains("http") {
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(x.trust_cert)
                    .gzip(true)
                    .brotli(true)
                    .timeout(Duration::from_secs(3))
                    .build()?;

                let start = Instant::now();
                let resp_r = client.get(url.as_str()).send().await;
                let resp_t = start.elapsed().as_millis();
                match resp_r {
                    Ok(val) => {
                        println!(" - Reponse: {} in {}ms", val.status(), resp_t);
                    },
                    Err(err) => println!(" - {}", err),
                }
            }
        }

        println!("")
    }

    Ok(())
}
