//! Contains the messages that the Server and the Certification Authority can exchange.

use wincode::config::Configuration;
use wincode::{ReadResult, SchemaRead, SchemaWrite, WriteResult};

#[derive(Debug, SchemaWrite, SchemaRead)]
pub enum Request {
    CertificateSign(Vec<u8>), // todo: add the cert type
}

#[derive(Debug, SchemaWrite, SchemaRead)]
pub enum Response {
    Ok,
}

const MAX_ALLOCATION_SIZE: usize = 4 * 1024 * 1024;

/// This formalizes the structure of our protocol.
const BINCODE_CONFIG: Configuration<
    true,
    MAX_ALLOCATION_SIZE,
    wincode::len::UseIntLen<u64, 0>,
    wincode::int_encoding::BigEndian,
> = Configuration::default()
    .with_big_endian()
    .with_fixint_encoding();

macro_rules! impl_network_message {
    ($t:ty) => {
        impl $t {
            pub fn serialize(&self) -> WriteResult<bytes::Bytes> {
                wincode::config::serialize(self, BINCODE_CONFIG).map(bytes::Bytes::from)
            }

            pub fn deserialize(bytes: impl AsRef<[u8]>) -> ReadResult<$t> {
                wincode::config::deserialize(bytes.as_ref(), BINCODE_CONFIG)
            }
        }
    };
}

impl_network_message!(Request);
impl_network_message!(Response);
