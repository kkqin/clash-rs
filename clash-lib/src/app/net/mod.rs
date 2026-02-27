use network_interface::{
    NetworkInterface, NetworkInterfaceConfig, V4IfAddr, V6IfAddr,
};
use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, LazyLock},
};

use serde::{Deserialize, Serialize};
use tracing::trace;

pub static DEFAULT_OUTBOUND_INTERFACE: LazyLock<
    Arc<tokio::sync::RwLock<Option<OutboundInterface>>>,
> = LazyLock::new(Default::default);
pub static TUN_SOMARK: LazyLock<tokio::sync::RwLock<Option<u32>>> =
    LazyLock::new(Default::default);

/// Initialize network configuration
/// globally manage default outbound interface
/// This function should be called as early as possible
/// so that other config initialization can use the default outbound interface
pub async fn init_net_config(tun_somark: Option<u32>) {
    *DEFAULT_OUTBOUND_INTERFACE.write().await = get_outbound_interface();
    *TUN_SOMARK.write().await = tun_somark;

    trace!(
        "default outbound interface: {:?}, tun somark: {:?}",
        *DEFAULT_OUTBOUND_INTERFACE.read().await,
        *TUN_SOMARK.read().await
    );
}

/// Represents a parsed outbound interface for use in runtime.
#[derive(Serialize, Debug, Clone)]
pub struct OutboundInterface {
    pub name: String,
    pub addr_v4: Option<Ipv4Addr>,
    pub netmask_v4: Option<Ipv4Addr>,
    pub broadcast_v4: Option<Ipv4Addr>,
    pub addr_v6: Option<Ipv6Addr>,
    pub netmask_v6: Option<Ipv6Addr>,
    pub broadcast_v6: Option<Ipv6Addr>,
    pub index: u32,
    pub mac_addr: Option<String>,
}

impl From<NetworkInterface> for OutboundInterface {
    fn from(iface: NetworkInterface) -> Self {
        fn get_outbound_ip_from_interface(
            iface: &NetworkInterface,
        ) -> (Option<V4IfAddr>, Option<V6IfAddr>) {
            let mut v4 = None;
            let mut v6 = None;

            for addr in iface.addr.iter() {
                trace!("inspect interface address: {:?} on {}", addr, iface.name);

                if v4.is_some() && v6.is_some() {
                    break;
                }

                match addr {
                    network_interface::Addr::V4(addr) => {
                        if !addr.ip.is_loopback()
                            && !addr.ip.is_link_local()
                            && !addr.ip.is_unspecified()
                        {
                            v4 = Some(*addr);
                        }
                    }
                    network_interface::Addr::V6(addr) => {
                        if addr.ip.is_unique_local() || addr.ip.is_global() {
                            v6 = Some(*addr);
                        }
                    }
                }
            }

            (v4, v6)
        }

        let addr = get_outbound_ip_from_interface(&iface);
        OutboundInterface {
            name: iface.name,
            addr_v4: addr.0.map(|x| x.ip),
            netmask_v4: addr.0.and_then(|x| x.netmask),
            broadcast_v4: addr.0.and_then(|x| x.broadcast),
            addr_v6: addr.1.map(|x| x.ip),
            netmask_v6: addr.1.and_then(|x| x.netmask),
            broadcast_v6: addr.1.and_then(|x| x.broadcast),
            index: iface.index,
            mac_addr: iface.mac_addr,
        }
    }
}
impl std::fmt::Display for OutboundInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (v4: {}, v6: {}, index: {}, mac: {})",
            self.name,
            self.addr_v4
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "None".to_string()),
            self.addr_v6
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "None".to_string()),
            self.index,
            self.mac_addr.clone().unwrap_or_else(|| "None".to_string())
        )
    }
}

pub fn get_interface_by_name(name: &str) -> Option<OutboundInterface> {
    let now = std::time::Instant::now();

    let outbound = network_interface::NetworkInterface::show()
        .ok()?
        .into_iter()
        .find(|iface| iface.name == name)?
        .into();

    trace!(
        "found interface by name: {:?}, took: {}ms",
        outbound,
        now.elapsed().as_millis()
    );

    Some(outbound)
}

pub fn get_outbound_interface() -> Option<OutboundInterface> {
    let now = std::time::Instant::now();

    let mut all_outbounds = network_interface::NetworkInterface::show()
        .ok()?
        .into_iter()
        .map(Into::into)
        .filter(|iface: &OutboundInterface| {
            !iface.name.contains("tun")
                && (iface.addr_v4.is_some() || iface.addr_v6.is_some())
        })
        .collect::<Vec<_>>();

    let priority: &[&str] = if cfg!(target_os = "android") {
        &[
            "wlan",  // Android Wi-Fi interface
            "rmnet", // Android mobile data interface
        ]
    } else if cfg!(target_os = "ios") {
        // iOS common interface names:
        // - en0: Wi-Fi
        // - pdp_ip0/pdp_ipX: cellular (multiple PDP contexts may exist)
        // Prefer Wi-Fi when it has a usable IP, otherwise fall back to cellular.
        &["en0", "en", "pdp_ip"]
    } else if cfg!(target_os = "windows") {
        &["Ethernet", "Wi-Fi", "Tailscale"]
    } else if cfg!(target_os = "linux") {
        &["eth", "wlp", "en", "Tailscale"]
    } else if cfg!(target_os = "macos") {
        &["en", "pdp_ip", "Tailscale"]
    } else {
        &["eth", "en", "wlp"]
    };

    all_outbounds.sort_by(|left, right| {
        fn v6_rank(addr: Option<Ipv6Addr>) -> u8 {
            match addr {
                Some(ip) if ip.is_unicast_global() => 0,
                Some(ip) if ip.is_unique_local() => 1,
                Some(_) => 2,
                None => 3,
            }
        }

        fn priority_rank(name: &str, priority: &[&str]) -> usize {
            priority
                .iter()
                .position(|needle| {
                    name == *needle
                        || name.starts_with(needle)
                        || name.contains(needle)
                })
                .unwrap_or(usize::MAX)
        }

        fn pdp_index(name: &str) -> Option<u32> {
            name.strip_prefix("pdp_ip")?.parse::<u32>().ok()
        }

        // iOS-specific behavior:
        // In practice, cellular `pdp_ip*` often has global IPv6 while Wi‑Fi `en0`
        // may only have IPv4. The previous sorting preferred IPv6 first, which
        // could cause `pdp_ip*` to win even when `en0` has a perfectly usable IPv4.
        // For iOS, we prioritize interface name (Wi‑Fi first) and only then compare
        // address quality.
        if cfg!(target_os = "ios") {
            let left_rank = priority_rank(&left.name, priority);
            let right_rank = priority_rank(&right.name, priority);
            if left_rank != right_rank {
                return left_rank.cmp(&right_rank);
            }

            // Among pdp_ip* interfaces, pick a deterministic one (lowest suffix).
            if left.name.starts_with("pdp_ip") && right.name.starts_with("pdp_ip") {
                match (pdp_index(&left.name), pdp_index(&right.name)) {
                    (Some(l), Some(r)) if l != r => return l.cmp(&r),
                    (Some(_), None) => return std::cmp::Ordering::Less,
                    (None, Some(_)) => return std::cmp::Ordering::Greater,
                    _ => {}
                }
            }

            // Prefer better IPv6 (global > ULA > others > none).
            let left_v6 = v6_rank(left.addr_v6);
            let right_v6 = v6_rank(right.addr_v6);
            if left_v6 != right_v6 {
                return left_v6.cmp(&right_v6);
            }

            // Prefer having IPv4 if all else ties.
            match (left.addr_v4.is_some(), right.addr_v4.is_some()) {
                (true, false) => return std::cmp::Ordering::Less,
                (false, true) => return std::cmp::Ordering::Greater,
                _ => {}
            }

            return left.name.cmp(&right.name);
        }

        // Default behavior for other OSes: prefer IPv6 first, then apply priority.
        match (left.addr_v6, right.addr_v6) {
            (Some(_), None) => return std::cmp::Ordering::Less,
            (None, Some(_)) => return std::cmp::Ordering::Greater,
            (Some(left), Some(right)) => {
                if left.is_unicast_global() && !right.is_unicast_global() {
                    return std::cmp::Ordering::Less;
                } else if !left.is_unicast_global() && right.is_unicast_global() {
                    return std::cmp::Ordering::Greater;
                }
            }
            _ => {}
        }

        let left = priority_rank(&left.name, priority);
        let right = priority_rank(&right.name, priority);
        left.cmp(&right)
    });

    trace!(
        "sorted outbound interfaces: {:?}, took: {}ms",
        all_outbounds,
        now.elapsed().as_millis()
    );

    all_outbounds.into_iter().next()
}

/// Represents a network interface in configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Interface {
    IpAddr(IpAddr),
    Name(String),
}

impl From<&str> for Interface {
    fn from(s: &str) -> Self {
        Self::Name(s.to_owned())
    }
}

impl From<IpAddr> for Interface {
    fn from(ip: IpAddr) -> Self {
        Self::IpAddr(ip)
    }
}

impl Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Interface::IpAddr(ip) => write!(f, "{ip}"),
            Interface::Name(name) => write!(f, "{name}"),
        }
    }
}

impl Interface {
    pub fn into_ip_addr(self) -> Option<IpAddr> {
        match self {
            Interface::IpAddr(ip) => Some(ip),
            _ => None,
        }
    }

    pub fn into_socket_addr(self) -> Option<SocketAddr> {
        match self {
            Interface::IpAddr(ip) => Some(SocketAddr::new(ip, 0)),
            _ => None,
        }
    }

    pub fn into_iface_name(self) -> Option<String> {
        match self {
            Interface::IpAddr(_) => None,
            Interface::Name(name) => Some(name),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::app::net::get_outbound_interface;

    #[test]
    fn test_get_outbound_interface() {
        let outbound = get_outbound_interface();
        print!("{:?}", outbound);
    }
}
