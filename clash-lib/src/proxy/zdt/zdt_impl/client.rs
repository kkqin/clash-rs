use super::{
    SECURITY_AES_256_CBC, Security,
    stream::{self},
};
use crate::{proxy::AnyStream, session::SocksAddr};
use std::io;

#[allow(dead_code)]
#[derive(Clone)]
pub struct ZdtOption {
    pub key: String,
    pub salt: String,
    pub iv: String,
    pub security: String,
    pub udp: bool,
    pub dst: SocksAddr,
}

pub struct Builder {
    pub is_udp: bool,
    pub key: String,
    pub security: Security,
    pub dst: SocksAddr,
}

impl Builder {
    pub fn new(opt: &ZdtOption) -> io::Result<Self> {
        let security = match opt.security.to_lowercase().as_str() {
            "aes256cbc" => SECURITY_AES_256_CBC,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid security",
                ));
            }
        };

        Ok(Self {
            is_udp: opt.udp,
            key: opt.key.clone(),
            security,
            dst: opt.dst.clone(),
        })
    }

    pub async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let stream = stream::ZdtStream::new(
            stream,
            &self.dst,
            self.key.clone(),
            &self.security,
            false,
            self.is_udp,
        )
        .await?;

        Ok(Box::new(stream))
    }
}
