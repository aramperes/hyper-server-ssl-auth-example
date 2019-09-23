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
use openssl::x509::X509Ref;
use openssl::x509::X509;
use rustls::{Certificate, PrivateKey};
use tokio::io::{self};
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
        let handler = acceptor.accept(tcp_stream).and_then(move |tls_stream| {
            let (tcp_stream, session) = tls_stream.get_ref();
            println!(
                "Received connection from peer {}",
                tcp_stream.peer_addr().unwrap()
            );

            // Read the CN from the client certificate using OpenSSL bindings
            // TODO: This seems to break when killing a keep-alive session?
            let client_cert = session.get_peer_certificates().unwrap().remove(0);
            let x509: &X509Ref = &X509::from_der(client_cert.as_ref()).unwrap();
            let cn = x509
                .subject_name()
                .entries_by_nid(Nid::COMMONNAME)
                .next()
                .unwrap()
                .data()
                .as_utf8()
                .unwrap()
                .to_string();

            // Create a Hyper service to handle HTTP
            let service = service_fn_ok(move |req| hello_world(req, cn.clone()));

            // Use the Hyper service using the decrypted stream
            let http = Http::new();
            http.serve_connection(tls_stream, service)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        });
        tokio::spawn(handler.map_err(|e| eprintln!("Error: {:}", e)));
        Ok(())
    });

    tokio::run(future.map_err(drop));
}

fn hello_world(_req: Request<Body>, cn: String) -> Response<Body> {
    Response::new(Body::from(format!("Hello, {}!\n", cn)))
}
