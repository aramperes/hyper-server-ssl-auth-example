# Hyper Server SSL Client-Cert Authentication

A sample Rust server that can process asynchronous HTTPS requests
and fetch the X.509 subject of the client-certificate used.

## Crates used

* **tokio**: async I/O and networking
* **hyper**: HTTP library, to send HTTP responses
* **rustls**/**tokio-rustls**: async TLS streams for tokio
* **openssl**: bindings to parse X.509 certs
