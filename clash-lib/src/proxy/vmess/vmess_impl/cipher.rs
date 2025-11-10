use aes_gcm::Aes128Gcm;
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;

use crate::common::crypto::AeadCipherHelper;

#[allow(clippy::large_enum_variant)]
pub enum VmessSecurity {
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl VmessSecurity {
    #[inline(always)]
    pub fn overhead_len(&self) -> usize {
        16
    }

    #[inline(always)]
    pub fn nonce_len(&self) -> usize {
        12
    }
}

pub(crate) struct AeadCipher {
    pub security: VmessSecurity,
    nonce: [u8; 32],
    iv: Bytes,
    count: u16,
}

impl AeadCipher {
    pub fn new(iv: &[u8], security: VmessSecurity) -> Self {
        Self {
            security,
            nonce: [0u8; 32],
            iv: Bytes::copy_from_slice(iv),
            count: 0,
        }
    }

    pub fn decrypt_inplace(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
    let mut nonce = self.nonce;
    let security = &self.security;
    let iv = &self.iv;
    let count = &mut self.count;

    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce[2..12].copy_from_slice(&iv[2..12]);
    // Avoid debug overflow panic; VMess uses a 16-bit counter in the nonce.
    // Wrap around on overflow to match modulo semantics.
    *count = count.wrapping_add(1);

        let nonce = &nonce[..security.nonce_len()];
        match security {
            VmessSecurity::Aes128Gcm(cipher) => {
                let dec =
                    cipher.decrypt_in_place_with_slice(nonce, &[], &mut buf[..]);
                if let Err(err) = dec {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        err.to_string(),
                    ));
                }
            }
            VmessSecurity::ChaCha20Poly1305(cipher) => {
                let dec =
                    cipher.decrypt_in_place_with_slice(nonce, &[], &mut buf[..]);
                if let Err(err) = dec {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        err.to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn encrypt_inplace(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
    let mut nonce = self.nonce;
    let security = &self.security;
    let iv = &self.iv;
    let count = &mut self.count;

    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce[2..12].copy_from_slice(&iv[2..12]);
    // Avoid debug overflow panic; VMess uses a 16-bit counter in the nonce.
    // Wrap around on overflow to match modulo semantics.
    *count = count.wrapping_add(1);

        let nonce = &nonce[..security.nonce_len()];
        match security {
            VmessSecurity::Aes128Gcm(cipher) => {
                cipher.encrypt_in_place_with_slice(nonce, &[], &mut buf[..]);
            }
            VmessSecurity::ChaCha20Poly1305(cipher) => {
                cipher.encrypt_in_place_with_slice(nonce, &[], &mut buf[..]);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::crypto::AeadCipherHelper;

    #[test]
    fn aead_counter_wraps_without_panic() {
        // Prepare a fixed key/iv; sizes are per VMess AEAD expectations
        let key = [0u8; 16];
        let iv = [1u8; 16];

        let security = VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(&key));
        let mut cipher = AeadCipher::new(&iv, security);

        // Force the counter to max to exercise wrapping behavior
        cipher.count = u16::MAX;

        // Buffer must include space for tag only (no plaintext)
        let mut buf = vec![0u8; cipher.security.overhead_len()];

        // Should not panic in debug builds and should succeed
        cipher.encrypt_inplace(&mut buf).expect("encrypt_inplace should succeed");

        // After wrapping add, count becomes 0
        assert_eq!(cipher.count, 0);
    }
}
