use dns_lookup::lookup_host;
use error::Result;
use openssl::asn1::*;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use openssl_sys::ASN1_TIME;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::os::raw::c_int;

extern "C" {
    fn ASN1_TIME_diff(
        pday: *mut c_int,
        psec: *mut c_int,
        from: *const ASN1_TIME,
        to: *const ASN1_TIME,
    );
}

pub struct SslExpiration(c_int);

impl SslExpiration {
    /// Creates new SslExpiration from domain name.
    ///
    /// This function will use the specified port to check SSL certificate.
    pub fn from_domain_name_with_port(domain: &str, port: u16) -> Result<SslExpiration> {
        SslExpiration::from_addr(domain, port, 3) // seconds
    }

    /// Creates new SslExpiration from SocketAddr.
    pub fn from_addr(domain: &str, port: u16, timeout: u64) -> Result<SslExpiration> {
        let context = {
            let mut context = SslContext::builder(SslMethod::tls())?;
            context.set_verify(SslVerifyMode::empty());
            context.build()
        };
        let mut connector = Ssl::new(&context)?;
        connector.set_hostname(domain)?;

        // TODO - Add safety check for the lookup host
        // Custom error which return DNS Failure - the main will retry with the ip directly
        let ips: Vec<std::net::IpAddr> = lookup_host(&domain).unwrap();
        let stream = TcpStream::connect_timeout(
            &SocketAddr::new(ips[0], port),
            std::time::Duration::from_secs(timeout),
        )?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(timeout)))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(timeout)))?;

        let stream = connector
            .connect(stream)
            .map_err(|e| error::ErrorKind::HandshakeError(e.to_string()))?;
        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or("Certificate not found")?;

        let now = Asn1Time::days_from_now(0)?;

        let (mut pday, mut psec) = (0, 0);
        let ptr_pday: *mut c_int = &mut pday;
        let ptr_psec: *mut c_int = &mut psec;
        let now_ptr = &now as *const _ as *const _;
        let after_ptr = &cert.not_after() as *const _ as *const _;
        unsafe {
            ASN1_TIME_diff(ptr_pday, ptr_psec, *now_ptr, *after_ptr);
        }

        Ok(SslExpiration(pday * 24 * 60 * 60 + psec))
    }

    /// How many seconds until SSL certificate expires.
    ///
    /// This function will return minus if SSL certificate is already expired.
    pub fn secs(&self) -> i32 {
        self.0
    }

    /// How many days until SSL certificate expires
    ///
    /// This function will return minus if SSL certificate is already expired.
    pub fn days(&self) -> i32 {
        self.0 / 86400
    }

    /// Returns true if SSL certificate is expired
    pub fn is_expired(&self) -> bool {
        self.0 < 0
    }
}

pub mod error {
    use std::io;

    error_chain! {
        foreign_links {
            OpenSslErrorStack(openssl::error::ErrorStack);
            IoError(io::Error);
        }
        errors {
            HandshakeError(e: String) {
                display("HandshakeError: {}", e)
            }
        }
    }
}
