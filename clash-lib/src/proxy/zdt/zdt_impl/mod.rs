mod cipher;
mod client;
mod stream;

type Security = u8;

pub(crate) const SECURITY_AES_256_CBC: Security = 1;

pub use client::{Builder, ZdtOption};
