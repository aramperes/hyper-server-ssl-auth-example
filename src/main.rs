extern crate hyper;
extern crate openssl;
extern crate rustls;
extern crate tokio;
extern crate tokio_rustls;

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use hyper::server::conn::Http;
use hyper::service::service_fn_ok;
use hyper::{Body, Request, Response};
use openssl::nid::Nid;
use openssl::x509::X509;
use rustls::{Certificate, PrivateKey};
use tokio::net::TcpListener;
use tokio::prelude::{Future, Stream};
use tokio_rustls::rustls::{AllowAnyAuthenticatedClient, RootCertStore, ServerConfig, Session};
use tokio_rustls::TlsAcceptor;

/// Load the server certificate
fn load_cert(filename: &str) -> Vec<Certificate> {
    let certfile = File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

/// Load the server private key
fn load_pkey(filename: &str) -> Vec<PrivateKey> {
    let keyfile = File::open(filename).expect("cannot open key file");
    let mut reader = BufReader::new(keyfile);
    rustls::internal::pemfile::pkcs8_private_keys(&mut reader).unwrap()
}

/// Load the SSL configuration for rustls
fn get_ssl_config() -> ServerConfig {
    // Trusted CA for client certificates
    let mut roots = RootCertStore::empty();
    let cafile = File::open("./ssl/inter.cert").expect("cannot open client ca file");
    let mut reader = BufReader::new(cafile);
    roots.add_pem_file(&mut reader).unwrap();

    let mut config = ServerConfig::new(AllowAnyAuthenticatedClient::new(roots));
    let server_cert = load_cert("./ssl/end.cert");
    let server_key = load_pkey("./ssl/end.key").remove(0);
    config
        .set_single_cert(server_cert, server_key)
        .expect("invalid key or certificate");

    config
}

fn main() {
    let addr = "127.0.0.1:3000".parse().unwrap();
    let config = get_ssl_config();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let socket = TcpListener::bind(&addr).unwrap();

    let future = socket.incoming().for_each(move |tcp_stream| {
        let handler = acceptor
            .accept(tcp_stream) // Decrypts the TCP stream
            .and_then(move |tls_stream| {
                let (tcp_stream, session) = tls_stream.get_ref();
                println!(
                    "Received connection from peer {}",
                    tcp_stream.peer_addr().unwrap()
                );

                // Get peer certificates from session
                let client_cert = match session.get_peer_certificates() {
                    None => return Err(io_err("did not receive any peer certificates")),
                    Some(mut peer_certs) => peer_certs.remove(0), // Get the first cert
                };

                // Parse X.509 certificate using OpenSSL bindings
                let x509 = &X509::from_der(client_cert.as_ref());
                let x509 = match x509 {
                    Err(_) => return Err(io_err("invalid X.509 peer certificate")),
                    Ok(x509) => x509,
                };

                let cn_entry = match x509.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
                    None => {
                        return Err(io_err(
                            "peer certificate does not contain a subject commonName",
                        ))
                    }
                    Some(entry) => entry,
                };

                let cn = match cn_entry.data().as_utf8() {
                    Err(_) => return Err(io_err("peer certificate commonName is not valid UTF-8")),
                    Ok(cn) => cn,
                };

                Ok((tls_stream, cn.to_string()))
            })
            .and_then(move |(tls_stream, cn)| {
                // Create a Hyper service to handle HTTP
                let service = service_fn_ok(move |req| hello_world(req, cn.clone()));

                // Use the Hyper service using the decrypted stream
                let http = Http::new();
                http.serve_connection(tls_stream, service)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            });
        tokio::spawn(handler.map_err(|e| eprintln!("Error: {:}", e)));
        Ok(())
    });

    tokio::run(future.map_err(drop));
}

fn hello_world(_req: Request<Body>, cn: String) -> Response<Body> {
    Response::new(Body::from(format!("Hello, {}!\n", cn)))
}

fn io_err(e: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}
