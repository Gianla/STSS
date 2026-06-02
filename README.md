# What's Simple TimeStamp Server (or STSS)?

STSS is an entire ecosystem including a Timestamp Server, a compatible client, a TLS certification authority and a 
custom network protocol.

A Timestamp Server is an authority that can provide signatures at a given time, proving that, according to said 
authority, a document existed in that specific time. Nowadays, many signature methods exist and are based on asymmetric 
encryption.

A timestamping authority binds the documents with the current timestamp before signing the entire bundle. This will 
prove to anyone that the document existed at that time, according to the authority.

# Fast setup

This project has been written in rust, so make sure you have `cargo` and `rust` installed. Refer to the [official rustup
guide](https://rust-book.cs.brown.edu/ch01-01-installation.html) to get it working easily.

The startup script `terraform` has been included to easily create a local environment that is already set up and ready 
to be tested. Just run
```bash
cargo run --bin terraform /path/to/root/environment
```
Inside the server, the CA and the client environment can be found, included of all the cryptographic utilities and the 
configuration `.toml` files. Configs may be adjusted as wanted (see below). All the three components only need the 
respective configuration file to be run:

### Server run
```bash
cargo run --bin server -- --config /path/to/your/server_config.toml
```

### Client run
```bash
cargo run --bin client_cli -- --config /path/to/your/client_config.toml
```

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

Obtaining the current time in order to sign a document can be also further configured to use a dedicated NTP server or 
the system's time. Just omit the `[synced_time_oracle]` if the local clock is trusted enough, or sync with the specified
NTP server when specifying the said section. Please note that this will also require to specify a UDP socket's address
to listen to the NTP server response.

# Disclaimer

This project was made for a University course, therefore, despite our effort to make it as reliable and secure as 
possible, it may contain errors and vulnerabilities that haven't been addressed. Furthermore, it is very rigid on some
practices. For example, the documents are strictly required in Sha256 and no other hashing algorithm; signing is 
strictly made by using RSA. Although this violates some programming principles, the course isn't about software
engineering and was made in a limited amount of time just to prove a point.

Enjoy.
