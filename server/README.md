# Server Configurations

The server has been made to be fully customizable from a `.toml` configuration file in order to adapt
to multiple systems. The `config.rs` module is responsible for parsing this information. A complete
example of how the server can be configured can be found below.

```toml
log="path/to/server_logs.txt"
database_path="path/to/server_database.sqlite"

[network]
ip="127.0.0.1"
port=8080

[runtime]
working_threads=4
cryptography_threads=0

[keys]
tls_cert_path="/etc/certs/tls_cert.pem"
tls_priv_path="/etc/certs/tls_priv.pem"
tss_priv_path="/etc/certs/tss_priv.pem"
ca_cert_path="/etc/certs/ca_cert.pem"

[synced_time_oracle]
ntp_server_host="pool.ntp.org" 
ntp_server_port=123 
listener_ip="0.0.0.0" 
listener_port=9000
sync_interval_in_minutes=60
```
