# What's Simple TimeStamp Server (or STSS)?

STSS is an entire ecosystem including a Timestamp Server, a compatible client library (and a local implementation as 
a cli), a TLS certification authority and a custom network protocol.

A Timestamp Server is an authority that can be asked to sign documents, proving that, according to said authority, 
a certain document existed in that specific time. Nowadays, many signature methods exist and are based on asymmetric 
encryption.

A timestamping authority binds the documents with the current timestamp before signing the entire bundle. This will 
prove to anyone that the document existed at that time, according to the authority.

# Fast setup

This project has been written in rust, so make sure you have `cargo` and `rust` installed. Refer to the [official rustup
guide](https://rust-book.cs.brown.edu/ch01-01-installation.html) to install them.

The startup script `terraform` has been included to easily create a local environment that is already set up and ready 
to be tested. Just run
```bash
cargo run --bin terraform /path/to/root/environment
```
Inside the new `/path/to/root/environment` dir, the server's, the CA's and the client's environments can be found, 
including all cryptographic utilities and the `.toml` configuration files. Those may be adjusted as wanted 
(check the READMEs inside the specific rust crate for further informations). All the three components only need the 
respective configuration file to be run, for example:

### Run the Server
```bash
cargo run --bin server -- --config /path/to/your/server_config.toml
```

### Run the Client's cli implementation
```bash
cargo run --bin client_cli -- --config /path/to/your/client_config.toml
```

### Run the CA
the CA is currently under development and will be available soon.


## Server configuration

The server's `.toml` file will appear with a `network` section that can be configured on the address to bind, for 
example:
```toml
[network]
ip = "127.0.0.1"
port = 8080
```

A `runtime` section will decide how many working threads the server will use to handle the connections (obviously, 
coroutines have been used, but they can be shared between threads):
```toml
[runtime]
working_threads = 4
cryptography_threads = 0
```
`cryptography_threads` are the threads reserved to signing operations. If set to zero, none will be dedicated to them, 
and they will simply block the working thread(s).
This is usually preferred if the system of the server supports hardware acceleration for heavy cryptography mathematical 
operations.

The server holds an `SQLite` database and a time syncing service that can be further configured. `terraform` already
generates the ones that we consider the most useful ones considering the average system and environment the server
will be run on. However, if it is wanted to obtain specific configurations, the Server's crate holds many more 
information on how to do so.

# Disclaimer

This project was made for a University course, therefore, despite our effort to make it as reliable and secure as 
possible, it may contain errors and vulnerabilities that haven't been addressed. Furthermore, it is very rigid on some
practices. For example, the documents are strictly required in Sha256 and no other hashing algorithm; signing is 
strictly made by using RSA. Although this violates some programming principles, the course isn't about software
engineering and was made in a limited amount of time just to prove a point.

Enjoy.
