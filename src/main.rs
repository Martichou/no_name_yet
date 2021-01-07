#[macro_use]
extern crate error_chain;
extern crate dotenv;
#[macro_use]
extern crate dotenv_codegen;

mod ssl_expire;

use dotenv::dotenv;
use log::error;
use serde::{Deserialize, Serialize};
use ssl_expire::SslExpiration;
use std::fs;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Debug, Deserialize)]
struct Server<'a> {
    host: &'a str,
    trust_cert: bool,
    port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message<'a> {
    login: &'a str,
    message: &'a str,
}

async fn send_alert(
    dest: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let timeout = Duration::new(5, 0);
    let client = reqwest::ClientBuilder::new()
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()?;

    let res = client
        .post("https://archibot.s19.be/sendMsgLogin")
        .header("Authorization", dotenv!("ARCHIBOT_KEY"))
        .json(&Message {
            login: dest,
            message: message,
        })
        .send()
        .await;

    match res {
        Ok(res) => println!("archibot: return status : {}", res.status()),
        Err(x) => {
            error!("calling error : {}", x);
        }
    }

    Ok(())
}

fn msg_ssl(days: i32, host: &str) -> String {
    format!(":closed_lock_with_key: *[SSL ALERT]* \n\nThe following host’s ssl expire in *{} days*.\n- {}\nPlease renew it before or your service will start to fail :cutevolt: ", days, host)
}

fn msg_err(host: &str, code: &str) -> String {
    format!(":closed_lock_with_key: *[WEB ALERT]* \n\nThe following host test resulted in an error.\n- {}\n- {}\n", host, code)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    std::env::set_var("RUST_LOG", "info");

    env_logger::init();

    dotenv().ok();

    let servers_json =
        fs::read_to_string("/Users/volt/Documents/Work/updown_clone/src/server.json")
            .expect("Unable to read file");
    let servers: Vec<Server> =
        serde_json::from_str(&servers_json).expect("JSON was not well-formatted");

    for x in servers {
        println!("{}", x.host);

        let mut url = Url::parse(&x.host)?;
        url.set_port(Some(x.port)).map_err(|_| "cannot be base")?;

        let host_str = url.host_str().expect("Failure in host_str");

        {
            // Check for the SSL Certs expiration
            let expiration = SslExpiration::from_domain_name_with_port(host_str, x.port);
            match expiration {
                Ok(val) => {
                    println!(" - SSL's expire in {} days", val.days());
                    if val.is_expired() || [30, 15, 10, 5, 1].contains(&val.days()) {
                        send_alert("Volt", &msg_ssl(val.days(), host_str)).await?;
                    }
                }
                Err(err) => println!(" - SSL check failed due to : {}", err),
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
                    }
                    Err(err) => {
                        println!(" - {}", err);
                        send_alert("Volt", &msg_err(host_str, &format!("{:?}", err))).await?;
                    }
                }
            }
        }

        println!("")
    }

    Ok(())
}
