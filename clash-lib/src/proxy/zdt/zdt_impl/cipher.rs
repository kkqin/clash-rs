use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use cbc::{
    Decryptor, Encryptor,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit},
};
use rand::{TryRngCore, rngs::OsRng};
use std::{cmp::PartialEq, io};

#[derive(PartialEq)]
pub enum ZdtSecurity {
    Aes256Cbc,
}

pub struct CbcCipher {
    security: ZdtSecurity,
    key: String,
}

// 类型别名
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

impl CbcCipher {
    pub fn new(key: String, security: ZdtSecurity) -> CbcCipher {
        Self { security, key }
    }

    pub fn decrypt_inplace(&mut self, buf: &mut [u8]) -> io::Result<Vec<u8>> {
        if self.security != ZdtSecurity::Aes256Cbc {
            return Err(io::ErrorKind::Unsupported.into());
        }
        if self.key.len() != 32 || buf.len() < 16 {
            return Err(io::ErrorKind::InvalidData.into());
        }

        let (iv, ciphertext) = buf.split_at(16);

        let cipher = Aes256CbcDec::new_from_slices(self.key.as_bytes(), iv)
            .map_err(|_| io::ErrorKind::Other)?;

        let mut ciphertext_vec = ciphertext.to_vec();

        let plaintext = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_vec)
            .map_err(|_| io::ErrorKind::InvalidData)?;
        Ok(plaintext.to_vec())
    }

    pub fn encrypt_inplace(&mut self, buf: &mut [u8]) -> io::Result<Vec<u8>> {
        if self.key.len() != 32 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // 生成 16 字节随机 IV
        let mut iv = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut iv)
            .map_err(|_| io::ErrorKind::Other)?;

        // 创建加密器
        let cipher = Aes256CbcEnc::new_from_slices(self.key.as_bytes(), &iv)
            .map_err(|_| io::ErrorKind::Other)?;

        // 使用 PKCS7 加密
        // 预留额外 block_size 的空间给 PKCS7 padding
        let block_size = 16;
        let mut plaintext = vec![0u8; buf.len() + block_size];
        plaintext[..buf.len()].copy_from_slice(buf);
        let ciphertext = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut plaintext, buf.len())
            .map_err(|_| io::ErrorKind::Other)?;

        // 输出为 [IV || Ciphertext]
        let mut output = Vec::with_capacity(iv.len() + ciphertext.len());
        output.extend_from_slice(&iv);
        output.extend_from_slice(ciphertext);
        Ok(output)
    }
}

#[test]
fn test_cbc_cipher() {
    let mut cbc = CbcCipher::new(
        "skeighdjskqiskalserdsq12djsdfrid".to_string(),
        ZdtSecurity::Aes256Cbc,
    );
    let mut buf = vec![5, 3, 0, 1, 2, 2, 2, 2];
    let hex_string: String = cbc
        .encrypt_inplace(&mut buf[..])
        .unwrap()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("{hex_string}");
}
