mod zdt_impl;

use super::DialWithConnector;
use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStream,
            ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    impl_default_connector,
    proxy::{
        AnyStream, ConnectorType, HandlerCommonOptions, OutboundHandler,
        OutboundType,
        transport::Transport,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
        socks::{socks_command, client_handshake},
    },
    session::Session,
};
use async_trait::async_trait;
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use tracing::debug;

#[derive(Default)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub security: String,
    pub key: String,
    pub salt: String,
    pub iv: String,
    pub udp: bool,
    pub tls: Option<Box<dyn Transport>>,
    pub transport: Option<Box<dyn Transport>>,
    pub mux: bool,
    pub mux_max_connections: usize,
}
pub struct Handler {
    opts: HandlerOptions,
    pool: Option<Arc<WsStreamPool>>,

    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZDT")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        let pool = if opts.mux {
            Some(Arc::new(WsStreamPool::new(opts.mux_max_connections)))
        } else {
            None
        };
        Self {
            opts,
            pool,
            connector: Default::default(),
        }
    }

    async fn build_transport_stream(
        &self,
        s: AnyStream,
    ) -> std::io::Result<AnyStream> {
        let s = if let Some(tls) = self.opts.tls.as_ref() {
            tls.proxy_stream(s).await?
        } else {
            s
        };

        let s = if let Some(transport) = self.opts.transport.as_ref() {
            transport.proxy_stream(s).await?
        } else {
            s
        };

        Ok(s)
    }

    async fn build_zdt_stream(
        &self,
        s: AnyStream,
        sess: &Session,
    ) -> std::io::Result<AnyStream> {
        // 先建立 ZDT 加密流，再在其上完成 SOCKS5 握手
        // 服务器期望 WebSocket 载荷始终是加密数据，包括握手内容
        let zdt_builder = zdt_impl::Builder::new(&zdt_impl::ZdtOption {
            key: self.opts.key.to_owned(),
            salt: self.opts.salt.to_owned(),
            iv: self.opts.iv.to_owned(),
            security: self.opts.security.to_owned(),
            udp: self.opts.udp,
            dst: sess.destination.clone(),
        })?;
        let mut s = zdt_builder.proxy_stream(s).await?;

        // 在 ZDT 层之上做 SOCKS5 握手，让远端 WS 服务转发到本地 Socks5
        client_handshake(
            &mut s,
            &sess.destination,
            socks_command::CONNECT,
            None,
            None,
        )
        .await?;

        Ok(s)
    }

    async fn get_transport_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<AnyStream> {
        if let Some(pool) = self.pool.as_ref() {
            if let Some(stream) = pool.take() {
                return Ok(
                    Box::new(PooledStream::new(stream, pool.clone()))
                        as AnyStream,
                );
            }
        }

        let s = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let s = self.build_transport_stream(s).await?;

        if let Some(pool) = self.pool.as_ref() {
            Ok(Box::new(PooledStream::new(s, pool.clone())) as AnyStream)
        } else {
            Ok(s)
        }
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Zdt
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_stream_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_datagram_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedStream> {
        let s = self.get_transport_stream(sess, resolver, connector).await?;
        let s = self.build_zdt_stream(s, sess).await?;
        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram_with_connector(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
        _connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedDatagram> {
        Err(std::io::Error::other("not implement"))
    }
}

struct WsStreamPool {
    max_size: usize,
    idle: Mutex<VecDeque<AnyStream>>,
}

impl WsStreamPool {
    fn new(max_size: usize) -> Self {
        Self {
            max_size: std::cmp::max(1, max_size),
            idle: Mutex::new(VecDeque::new()),
        }
    }

    fn take(&self) -> Option<AnyStream> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.pop_front()
    }

    fn put(&self, stream: AnyStream) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < self.max_size {
            idle.push_back(stream);
        }
    }
}

struct PooledStream {
    inner: Option<AnyStream>,
    pool: Arc<WsStreamPool>,
    broken: bool,
}

impl PooledStream {
    fn new(inner: AnyStream, pool: Arc<WsStreamPool>) -> Self {
        Self {
            inner: Some(inner),
            pool,
            broken: false,
        }
    }

    fn inner_mut(&mut self) -> Option<&mut AnyStream> {
        self.inner.as_mut()
    }
}

impl AsyncRead for PooledStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = match this.inner_mut() {
            Some(inner) => inner,
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stream closed",
                )))
            }
        };
        let poll = Pin::new(inner.as_mut()).poll_read(cx, buf);
        if let Poll::Ready(Err(_)) = &poll {
            this.broken = true;
        }
        poll
    }
}

impl AsyncWrite for PooledStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let inner = match this.inner_mut() {
            Some(inner) => inner,
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stream closed",
                )))
            }
        };
        let poll = Pin::new(inner.as_mut()).poll_write(cx, buf);
        if let Poll::Ready(Err(_)) = &poll {
            this.broken = true;
        }
        poll
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = match this.inner_mut() {
            Some(inner) => inner,
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stream closed",
                )))
            }
        };
        let poll = Pin::new(inner.as_mut()).poll_flush(cx);
        if let Poll::Ready(Err(_)) = &poll {
            this.broken = true;
        }
        poll
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = match this.inner_mut() {
            Some(inner) => inner,
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stream closed",
                )))
            }
        };
        let poll = Pin::new(inner.as_mut()).poll_shutdown(cx);
        if let Poll::Ready(Err(_)) = &poll {
            this.broken = true;
        }
        poll
    }
}

impl Drop for PooledStream {
    fn drop(&mut self) {
        if self.broken {
            return;
        }

        if let Some(inner) = self.inner.take() {
            self.pool.put(inner);
        }
    }
}
