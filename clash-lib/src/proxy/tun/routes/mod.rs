#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::add_route;
#[cfg(windows)]
pub use windows::maybe_routes_clean_up;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::add_route;
#[cfg(target_os = "macos")]
pub use macos::maybe_routes_clean_up;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::add_route;
#[cfg(target_os = "linux")]
pub use linux::maybe_routes_clean_up;

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod other;
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
use other::add_route;
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub use other::maybe_routes_clean_up;

use std::{collections::HashSet, io, net::IpAddr, time::Duration};
use tracing::{error, warn};

use crate::{
    app::net::get_interface_by_name, config::internal::config::TunConfig,
};

#[cfg(target_os = "macos")]
use crate::runner::Runner;
#[cfg(target_os = "macos")]
use futures::future::BoxFuture;
#[cfg(target_os = "macos")]
use std::sync::LazyLock;
#[cfg(target_os = "macos")]
use tokio::sync::broadcast;
#[cfg(target_os = "macos")]
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "macos")]
static NETCHANGE_TX: LazyLock<broadcast::Sender<()>> = LazyLock::new(|| {
    let (tx, _rx) = broadcast::channel(16);
    tx
});

#[cfg(target_os = "macos")]
static HOST_ROUTE_REGISTRY: LazyLock<tokio::sync::RwLock<HashSet<IpAddr>>> =
    LazyLock::new(|| tokio::sync::RwLock::new(HashSet::new()));

#[cfg(target_os = "macos")]
pub fn subscribe_netchange() -> broadcast::Receiver<()> {
    NETCHANGE_TX.subscribe()
}

#[cfg(target_os = "macos")]
pub async fn register_host_route_target(ip: IpAddr) {
    HOST_ROUTE_REGISTRY.write().await.insert(ip);
}

#[cfg(target_os = "macos")]
pub fn ensure_host_route(ip: IpAddr) {
    let _ = macos::maybe_add_host_route_for_addr(&ip);
}

#[cfg(target_os = "macos")]
/// Best-effort cleanup of any registered host routes (e.g., DNS servers like 1.1.1.1).
/// This function is synchronous and uses try_* locks to avoid blocking in shutdown paths.
pub fn cleanup_host_routes() {
    // Snapshot the list without awaiting
    if let Ok(guard) = HOST_ROUTE_REGISTRY.try_read() {
        let ips: Vec<IpAddr> = guard.iter().cloned().collect();
        drop(guard);
        for ip in ips {
            let _ = macos::maybe_delete_host_route_for_addr(&ip);
        }
    }

    // Clear registry (best-effort)
    if let Ok(mut w) = HOST_ROUTE_REGISTRY.try_write() {
        w.clear();
    }
}

#[cfg(target_os = "macos")]
async fn reapply_host_routes() {
    let ips: Vec<IpAddr> = HOST_ROUTE_REGISTRY.read().await.iter().cloned().collect();
    for ip in ips {
        // Force refresh: delete then add to move to the new default interface/gateway.
        #[cfg(target_os = "macos")]
        {
            let _ = macos::maybe_delete_host_route_for_addr(&ip);
            let _ = macos::maybe_add_host_route_for_addr(&ip);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = ip; // no-op on other platforms
        }
    }
}

#[allow(dead_code)]
pub fn maybe_add_routes(cfg: &TunConfig, tun_name: &str) -> std::io::Result<()> {
    if cfg.route_all || !cfg.routes.is_empty() {
        #[cfg(target_os = "linux")]
        linux::check_ip_command_installed()?;

        let tun_iface = get_interface_by_name(tun_name).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("tun interface {} not found", tun_name),
            )
        })?;

        if cfg.route_all {
            warn!(
                "route_all is enabled, all traffic will be routed through the tun \
                 interface"
            );

            #[cfg(not(target_os = "linux"))]
            {
                use ipnet::IpNet;

                use std::net::Ipv4Addr;

                let mut default_routes = vec![
                    IpNet::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1)
                        .unwrap(),
                    IpNet::new(std::net::IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)
                        .unwrap(),
                ];

                if tun_iface.addr_v6.is_some() {
                    // Add default IPv6 route
                    default_routes.append(&mut vec![
                        IpNet::new(
                            std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                                0, 0, 0, 0, 0, 0, 0, 0,
                            )),
                            1,
                        )
                        .unwrap(),
                        IpNet::new(
                            std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                                0x8000, 0, 0, 0, 0, 0, 0, 0,
                            )),
                            1,
                        )
                        .unwrap(),
                    ]);
                }

                for r in default_routes {
                    add_route(&tun_iface, &r)?;
                }

                #[cfg(target_os = "windows")]
                {
                    // Set DNS server or DNS hijack won't work
                    // We can't set name server to clash DNS listener address
                    // because it may not be on standard port 53
                    // Windows only support DNS server on port 53
                    if cfg.dns_hijack {
                        warn!(
                            "DNS hijack is enabled, setting fake DNS servers for \
                             the tun interface"
                        );
                        let name_server = vec!["1.1.1.1".parse().unwrap()];
                        let _ = windows::set_dns_v4(&tun_iface, &name_server)
                            .map_err(|e| {
                                tracing::error!("failed to set dns due to:{}", e)
                            });
                        let name_server_v6 =
                            vec!["2606:4700:4700::1111".parse().unwrap()];
                        let _ = windows::set_dns_v6(&tun_iface, &name_server_v6)
                            .map_err(|e| {
                                tracing::error!("failed to set dns due to:{}", e)
                            });
                    }
                }
                #[cfg(target_os = "macos")]
                {
                    macos::maybe_add_default_route()?;
                    // Keep system services (mDNS/AWDL/AirPlay, etc.) working by bypassing
                    // multicast and link-local traffic around the TUN.
                    let _ = macos::maybe_add_system_bypass_routes().map_err(|e| {
                        warn!("failed to add system bypass routes: {:?}", e);
                        e
                    });
                }
            }
            #[cfg(target_os = "linux")]
            {
                linux::setup_policy_routing(cfg, &tun_iface)?;
            }
        } else {
            for r in &cfg.routes {
                add_route(&tun_iface, r)?;
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub struct RouteMonitorRunner {
    enable: bool,
    cancellation_token: CancellationToken,
}

#[cfg(target_os = "macos")]
impl RouteMonitorRunner {
    pub fn new(
        enable: bool,
        cancellation_token: Option<CancellationToken>,
    ) -> Self {
        Self {
            enable,
            cancellation_token: cancellation_token.unwrap_or_default(),
        }
    }

    async fn monitor(cancellation_token: CancellationToken) {
        let mut backoff_secs = 1u64;
        let mut last_fix: Option<std::time::Instant> = None;

        'restart: loop {
            if cancellation_token.is_cancelled() {
                break 'restart;
            }

            // open routing socket
            let rtsock = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
            if rtsock < 0 {
                error!(
                    "failed to open route socket: {:?}",
                    io::Error::last_os_error()
                );
                std::thread::sleep(Duration::from_secs(backoff_secs));
                backoff_secs = (backoff_secs * 2).min(60);
                continue 'restart;
            }

            // shorter timeout for faster stop/retry
            let tv = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            unsafe {
                libc::setsockopt(
                    rtsock,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }

            warn!("route monitor started (fd={})", rtsock);
            backoff_secs = 1;

            let mut buf = vec![0u8; 4096];

            // inner read loop
            loop {
                if cancellation_token.is_cancelled() {
                    warn!("route monitor stopping as requested");
                    unsafe { libc::close(rtsock) };
                    break 'restart;
                }

                let n = unsafe {
                    libc::read(
                        rtsock,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };

                if n <= 0 {
                    let err = io::Error::last_os_error();
                    // timeout -> continue; fatal -> break to restart; other -> warn
                    // and continue
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::TimedOut
                    {
                        continue;
                    }

                    match err.raw_os_error() {
                        Some(code)
                            if code == libc::EBADF || code == libc::ENOTCONN =>
                        {
                            error!("route monitor fatal error: {:?}", err);
                            // close and restart
                            unsafe { libc::close(rtsock) };
                            std::thread::sleep(Duration::from_secs(backoff_secs));
                            backoff_secs = (backoff_secs * 2).min(60);
                            continue 'restart;
                        }
                        _ => {
                            warn!("route monitor read error: {:?}", err);
                            // small backoff for transient errors
                            std::thread::sleep(Duration::from_millis(200));
                            continue;
                        }
                    }
                }

                if (n as usize) < std::mem::size_of::<libc::rt_msghdr>() {
                    continue;
                }

                // Safe after length check above
                let rtm: &libc::rt_msghdr =
                    unsafe { &*(buf.as_ptr() as *const libc::rt_msghdr) };

                match rtm.rtm_type as i32 {
                    libc::RTM_DELETE | libc::RTM_CHANGE => {
                        if macos::has_default_route(rtm) {
                            // debounce to avoid thrashing
                            let now = std::time::Instant::now();
                            if last_fix
                                .map(|t| now.duration_since(t) < Duration::from_secs(3))
                                .unwrap_or(false)
                            {
                                continue;
                            }

                            warn!(
                                "route socket event type={} flags=0x{:x}",
                                rtm.rtm_type, rtm.rtm_flags
                            );
                            last_fix = Some(now);
                            if let Err(err) = macos::maybe_add_default_route() {
                                error!("maybe_add_default_route error: {:?}", err);
                            } else {
                                warn!("maybe_add_default_route succeeded");
                            }

                            // Re-apply any registered host routes (best-effort)
                            reapply_host_routes().await;

                            // Broadcast a netchange event to subscribers (e.g., outbound manager)
                            let _ = NETCHANGE_TX.send(());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl Runner for RouteMonitorRunner {
    fn run_async(&self) {
        if !self.enable {
            return;
        }

        let cancellation_token = self.cancellation_token.clone();
        tokio::spawn(async move {
            RouteMonitorRunner::monitor(cancellation_token).await;
        });
    }

    fn shutdown(&self) {
        warn!("shutting down route monitor");
        self.cancellation_token.cancel();
    }

    fn join(&self) -> BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async { Ok(()) })
    }
}
