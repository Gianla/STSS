//! Implements some utilities for big-endian to host conversion, strongly typing big-endian numbers
//! to avoid confusion.

use wincode::{SchemaRead, SchemaWrite};

/// Macro to avoid error-prone and repetitive definitions.
macro_rules! define_network_type {
    ($name:ident, $type:ty, $size:expr) => {
        /// Big-endian number that implements in/equality operations and de/serialization.
        #[derive(SchemaWrite, SchemaRead, Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name {
            n: [u8; $size],
        }

        impl $name {
            /// Creates a big-endian number from a host number.
            pub fn from_host(n: $type) -> Self {
                Self { n: n.to_be_bytes() }
            }

            /// Converts the big-endian number to a host number.
            pub fn to_host(&self) -> $type {
                <$type>::from_be_bytes(self.n)
            }
        }

        /// Allows the from() method to be implemented for big-endian numbers.
        impl From<$type> for $name {
            fn from(host_val: $type) -> Self {
                Self::from_host(host_val)
            }
        }

        /// Allows each normal number to be converted into big-endian with a from() method.
        impl From<$name> for $type {
            fn from(net_val: $name) -> Self {
                net_val.to_host()
            }
        }
    };
}

define_network_type!(NetworkShort, u16, 2);
define_network_type!(NetworkLong, u32, 4);
define_network_type!(NetworkLongLong, u64, 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_short_conversion() {
        let host_val: u16 = 0x1234;
        let net_val = NetworkShort::from_host(host_val);

        assert_eq!(net_val.n, [0x12, 0x34]);
        assert_eq!(net_val.to_host(), host_val);
    }

    #[test]
    fn test_network_long_traits() {
        let original: u32 = 0xAABBCCDD;

        let net_val = NetworkLong::from(original);
        assert_eq!(net_val.n, [0xAA, 0xBB, 0xCC, 0xDD]);

        let back_to_host: u32 = net_val.into();
        assert_eq!(back_to_host, original);
    }

    #[test]
    fn test_equality_and_derives() {
        let a = NetworkLongLong::from_host(100);
        let b = NetworkLongLong::from(100u64);
        let c = NetworkLongLong::from_host(200);

        assert_eq!(a, b);
        assert_ne!(a, c);

        let cloned = a;
        assert_eq!(cloned, a);
    }

    #[test]
    fn test_edge_cases() {
        assert_eq!(NetworkShort::from_host(0).to_host(), 0);

        assert_eq!(NetworkShort::from_host(u16::MAX).to_host(), u16::MAX);
        assert_eq!(NetworkLong::from_host(u32::MAX).to_host(), u32::MAX);
        assert_eq!(NetworkLongLong::from_host(u64::MAX).to_host(), u64::MAX);
    }
}
