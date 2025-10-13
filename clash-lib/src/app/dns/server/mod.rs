use hickory_proto::op::Message;

use tracing::{debug, error, instrument, info, warn};
use std::time::Duration;
use watfaq_dns::DNSListenAddr;

use crate::Runner;

use super::ThreadSafeDNSResolver;

mod handler;
pub use handler::exchange_with_resolver;

static DEFAULT_DNS_SERVER_TTL: u32 = 60;

struct DnsMessageExchanger {
    resolver: ThreadSafeDNSResolver,
}

impl watfaq_dns::DnsMessageExchanger for DnsMessageExchanger {
    fn ipv6(&self) -> bool {
        self.resolver.ipv6()
    }

    #[instrument(skip(self))]
    async fn exchange(
        &self,
        message: &Message,
    ) -> Result<Message, watfaq_dns::DNSError> {
        exchange_with_resolver(&self.resolver, message, true).await
    }
}

pub async fn get_dns_listener(
    listen: DNSListenAddr,
    resolver: ThreadSafeDNSResolver,
    cwd: &std::path::Path,
) -> Option<Runner> {
    let listen = listen;
    let resolver = resolver;
    let cwd = cwd.to_path_buf();

    // Try to get an initial listener; if none configured, return None.
    let initial = watfaq_dns::get_dns_listener(listen.clone(), DnsMessageExchanger { resolver: resolver.clone() }, &cwd).await;
    match initial {
        Some(runner) => Some(Box::pin(async move {
            // When a listener exists, keep it running and automatically
            // recreate it on transient errors (like UDP socket close triggered
            // by route/interface changes). This loop will only bail out on
            // non-transient errors.
            let mut r = runner;
            loop {
                match r.await {
                    Ok(()) => {
                        info!("dns listener exited normally");
                        return Ok(());
                    }
                    Err(err) => {
                        error!("dns listener error: {}", err);
                        let s = err.to_string();

                        // Detect transient error patterns (UDP socket closed etc.)
                        if s.contains("unexpected close of UDP socket")
                            || s.contains("dns proxy outbound is closed")
                            || s.contains("connection reset")
                            || s.contains("socket")
                        {
                            warn!("transient dns listener error, will restart: {}", s);
                            tokio::time::sleep(Duration::from_millis(500)).await;

                            // Try to recreate the listener. If recreation returns
                            // None, the configuration no longer requests a listener,
                            // so exit cleanly.
                            match watfaq_dns::get_dns_listener(listen.clone(), DnsMessageExchanger { resolver: resolver.clone() }, &cwd).await {
                                Some(new_runner) => {
                                    r = new_runner;
                                    continue;
                                }
                                None => {
                                    info!("dns listener recreation returned None, exiting");
                                    return Ok(());
                                }
                            }
                        }

                        // Non-transient error: bubble up
                        return Err(err.into());
                    }
                }
            }
        })),
        None => None,
    }
}
