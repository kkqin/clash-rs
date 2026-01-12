use super::{SECURITY_AES_256_CBC, Security, cipher::CbcCipher};
use crate::{
    proxy::zdt::zdt_impl::cipher::ZdtSecurity::Aes256Cbc, session::SocksAddr,
};
use bytes::BytesMut;
use futures::ready;
use std::{fmt::Debug, io, pin::Pin, task::Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

pub struct ZdtStream<S> {
    stream: S,
    dst: SocksAddr,
    cbc_cipher: Option<CbcCipher>,
    security: u8,
    is_udp: bool,
    write_buf: BytesMut, // 追加此字段
    write_state: WriteState,
    read_buf: BytesMut,
    temp_buf: BytesMut, // rec
    read_state: ReadState,
}

enum WriteState {
    BuildingData,
    FlushingData {
        consumed: usize,
        total: usize,
        written: usize,
    },
}

enum ReadState {
    WaitingHeader,
    WaitingData,
    FlushingData(usize), // 剩余数据量
}

impl<S> Debug for ZdtStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZdtStream")
            .field("dst", &self.dst)
            .field("is_udp", &self.is_udp)
            .field("security", &self.security)
            .finish()
    }
}

impl<S> ZdtStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) async fn new(
        stream: S,
        dst: &SocksAddr,
        key: String,
        security: &Security,
        is_aead: bool,
        is_udp: bool,
    ) -> io::Result<ZdtStream<S>> {
        if is_aead {
            return Err(io::ErrorKind::Unsupported.into());
        }

        let cipher = match *security {
            SECURITY_AES_256_CBC => Some(CbcCipher::new(key, Aes256Cbc)),
            _ => None,
        };

        let stream = Self {
            stream,
            dst: dst.to_owned(),
            security: *security,
            cbc_cipher: cipher,
            is_udp,
            write_buf: BytesMut::new(),
            write_state: WriteState::BuildingData,
            read_buf: BytesMut::new(),
            read_state: ReadState::WaitingHeader,
            temp_buf: BytesMut::new(),
        };
        Ok(stream)
    }
}

impl<S> AsyncRead for ZdtStream<S>
where
    S: AsyncRead + Unpin + Send,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.read_state {
                ReadState::WaitingHeader => {
                    self.read_state = ReadState::WaitingData;
                }

                ReadState::WaitingData => {
                    let this = &mut *self;
                    // 暂时分配一块读取缓冲（最大 4KB），你可根据需求扩展
                    let mut temp = [0u8; 4096];
                    let mut read_buf = ReadBuf::new(&mut temp);

                    match ready!(
                        Pin::new(&mut this.stream).poll_read(cx, &mut read_buf)
                    ) {
                        Ok(_) => {debug!("")},
                        Err(e) => {
                            debug!("{e}");
                            return Poll::Ready(Err(e));
                        }
                    };
                    let filled = read_buf.filled();

                    if filled.is_empty() {
                        return Poll::Ready(
                            Err(io::ErrorKind::UnexpectedEof.into()),
                        );
                    }

                    // 追加数据到临时缓冲
                    this.temp_buf.extend_from_slice(filled);

                    // 是否对齐 block size（例如 AES 为 16）
                    let block_size = 16;
                    if this.temp_buf.len() % block_size != 0 {
                        return Poll::Pending; // 还不能解密
                    }

                    // clone 一份尝试解密，防止 padding 解失败时污染 buffer
                    let mut try_decrypt = this.temp_buf.clone();
                    match this
                        .cbc_cipher
                        .as_mut()
                        .unwrap()
                        .decrypt_inplace(&mut try_decrypt)
                    {
                        Ok(decrypted) => {
                            this.read_buf.clear();
                            this.read_buf.extend_from_slice(&decrypted);
                            this.temp_buf.clear();
                            this.read_state =
                                ReadState::FlushingData(this.read_buf.len());
                        }
                        Err(_) => {
                            // padding不完整？继续等更多数据
                            return Poll::Pending;
                        }
                    }
                }

                ReadState::FlushingData(size) => {
                    let this = &mut *self;
                    let to_copy = std::cmp::min(size, buf.remaining());

                    buf.put_slice(&this.read_buf.split_to(to_copy));

                    if to_copy < size {
                        this.read_state = ReadState::FlushingData(size - to_copy);
                    } else {
                        this.read_state = ReadState::WaitingHeader;
                    }

                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> ZdtStream<S> {
    fn encrypt_and_prepare(&mut self, buf: &[u8]) -> io::Result<()> {
        // 加密 buf，填充 write_buf
        let mut buf_mut = buf.to_vec();
        let encrypted = self
            .cbc_cipher
            .as_mut()
            .unwrap()
            .encrypt_inplace(&mut buf_mut)?;

        self.write_buf.clear();
        self.write_buf.extend_from_slice(&encrypted);
        Ok(())
    }
}

impl<S> AsyncWrite for ZdtStream<S>
where
    S: AsyncWrite + Unpin + Send,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            match self.write_state {
                WriteState::BuildingData => {
                    // 如果没数据，先加密并放进缓冲
                    if buf.is_empty() {
                        // 没数据写，直接返回0
                        return Poll::Ready(Ok(0));
                    }
                    // 准备写缓冲
                    if let Err(e) = self.encrypt_and_prepare(buf) {
                        return Poll::Ready(Err(e));
                    }
                    let total = self.write_buf.len();
                    // 进入写数据状态，记明文消耗长度（等于buf.len()）
                    self.write_state = WriteState::FlushingData {
                        consumed: buf.len(),
                        total,
                        written: 0,
                    };
                }
                WriteState::FlushingData {
                    consumed,
                    total,
                    written,
                } => {
                    // 继续写剩余数据
                    let this = self.as_mut().get_mut();
                    let n = ready!(
                        Pin::new(&mut this.stream)
                            .poll_write(cx, &this.write_buf[written..total])
                    )?;
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    let new_written = written + n;
                    if new_written >= total {
                        // 写完当前包，切换回 BuildingData 状态
                        self.write_state = WriteState::BuildingData;
                        return Poll::Ready(Ok(consumed));
                    } else {
                        // 还没写完，更新写入状态，继续等待写入完成
                        self.write_state = WriteState::FlushingData {
                            consumed,
                            total,
                            written: new_written,
                        };
                    }
                }
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let Self { stream, .. } = self.get_mut();
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let Self { stream, .. } = self.get_mut();
        Pin::new(stream).poll_shutdown(cx)
    }
}
