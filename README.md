# Hyper Server SSL Client-Cert Authentication

> ⚠️ 2023-12-30: This repository is quite old (by Rust standards); an updated example can be found here: https://github.com/thomasarmel/hyper-https-server-client-auth

A sample Rust server that can process asynchronous HTTPS requests
and fetch the X.509 subject of the client-certificate used.

## Crates used

* **tokio**: async I/O and networking
* **hyper**: HTTP library, to send HTTP responses
* **rustls**/**tokio-rustls**: async TLS streams for tokio
* **x509-parser**: to parse X.509 client certificates
