use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use tracing::warn;

use crate::{
    app::net::{OutboundInterface, get_outbound_interface},
    common::errors::new_io_error,
    config::internal::config::TunConfig,
};

use libc;
use std::mem;

/// let's assume that the `route` command is available on macOS
pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let mut cmd = std::process::Command::new("route");
    cmd.arg("add");

    match dest {
        IpNet::V4(_) => {
            cmd.arg("-net")
                .arg(dest.to_string())
                .arg("-interface")
                .arg(&via.name);
            warn!("executing: route add -net {} -interface {}", dest, via.name);
        }
        IpNet::V6(_) => {
            cmd.arg("-inet6")
                .arg(dest.to_string())
                .arg("-interface")
                .arg(&via.name);
            warn!(
                "executing: route add -inet6 {} -interface {}",
                dest, via.name
            );
        }
    }

    let output = cmd.output()?;

    if !output.status.success() {
        Err(new_io_error("add route failed"))
    } else {
        Ok(())
    }
}

fn get_default_gateway()
-> std::io::Result<(Option<Ipv4Addr>, Option<std::net::Ipv6Addr>)> {
    // IPv4
    let cmd_v4 = std::process::Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("default")
        .output()?;

    let mut gateway_v4 = None;
    if cmd_v4.status.success() {
        let output = String::from_utf8_lossy(&cmd_v4.stdout);
        for line in output.lines() {
            if line.trim().contains("gateway:") {
                gateway_v4 = line
                    .split_whitespace()
                    .last()
                    .and_then(|x| x.parse::<Ipv4Addr>().ok());
                break;
            }
        }
    }

    // IPv6
    let cmd_v6 = std::process::Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("-inet6")
        .arg("default")
        .output()?;

    let mut gateway_v6 = None;
    if cmd_v6.status.success() {
        let output = String::from_utf8_lossy(&cmd_v6.stdout);
        for line in output.lines() {
            if line.trim().contains("gateway:") {
                gateway_v6 = line
                    .split_whitespace()
                    .last()
                    .and_then(|x| x.parse::<std::net::Ipv6Addr>().ok());
                break;
            }
        }
    }

    Ok((gateway_v4, gateway_v6))
}

/// it seems to be fine to add the default route multiple times
pub fn maybe_add_default_route() -> std::io::Result<()> {
    let (gateway_v4, gateway_v6) = get_default_gateway()?;
    let default_interface =
        get_outbound_interface().ok_or(new_io_error("get default interface"))?;

    // Add IPv4 default route if gateway found
    if let Some(gateway) = gateway_v4 {
        let cmd = std::process::Command::new("route")
            .arg("add")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("0/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route add -ifscope {} 0/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            return Err(new_io_error("add default route failed"));
        }
    }

    if let Some(gateway) = gateway_v6 {
        let cmd = std::process::Command::new("route")
            .arg("add")
            .arg("-inet6")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("::/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route add -inet6 -ifscope {} ::/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            return Err(new_io_error("add default IPv6 route failed"));
        }
    }

    if gateway_v4.is_none() {
        Err(new_io_error(
            "cant set default route, default gateway not found",
        ))
    } else {
        Ok(())
    }
}

/// Add essential bypass routes for system services that use multicast and link-local
/// networking (mDNS, AWDL/AirDrop, AirPlay, etc.). Without these, route_all may
/// hijack 224.0.0.0/4 and ff00::/8 into the utun, breaking Apple daemons like remoted.
pub fn maybe_add_system_bypass_routes() -> std::io::Result<()> {
    let default_interface =
        get_outbound_interface().ok_or(new_io_error("get default interface"))?;

    // IPv4 multicast and link-local subnets
    let bypass_v4: [(&str, &str); 2] = [("224.0.0.0/4", "-net"), ("169.254.0.0/16", "-net")];
    for (cidr, kind) in bypass_v4 {
        let mut cmd = std::process::Command::new("route");
        cmd.arg("add")
            .arg(kind)
            .arg(cidr)
            .arg("-interface")
            .arg(&default_interface.name);

        warn!(
            "executing: route add {} {} -interface {}",
            kind, cidr, default_interface.name
        );
        let out = cmd.output()?;
        if !out.status.success() {
            // Don't hard fail; keep best-effort behavior
            warn!("failed to add IPv4 bypass route {} on {}", cidr, default_interface.name);
        }
    }

    // IPv6 multicast and link-local subnets
    let bypass_v6: [&str; 2] = ["ff00::/8", "fe80::/10"]; // multicast, link-local
    for cidr in bypass_v6 {
        let mut cmd = std::process::Command::new("route");
        cmd.arg("add")
            .arg("-inet6")
            .arg(cidr)
            .arg("-interface")
            .arg(&default_interface.name);

        warn!(
            "executing: route add -inet6 {} -interface {}",
            cidr, default_interface.name
        );
        let out = cmd.output()?;
        if !out.status.success() {
            warn!(
                "failed to add IPv6 bypass route {} on {}",
                cidr, default_interface.name
            );
        }
    }

    Ok(())
}

/// Add a host-specific route for a unicast destination to ensure it follows
/// the current default physical interface and gateway (bypassing utun/route_all).
pub(crate) fn maybe_add_host_route_for_addr(ip: &std::net::IpAddr) -> std::io::Result<()> {
    let (gateway_v4, gateway_v6) = get_default_gateway()?;
    let default_interface =
        get_outbound_interface().ok_or(new_io_error("get default interface"))?;

    match ip {
        std::net::IpAddr::V4(v4) => {
            if let Some(gw) = gateway_v4 {
                let out = std::process::Command::new("route")
                    .arg("add")
                    .arg("-host")
                    .arg(v4.to_string())
                    .arg("-ifscope")
                    .arg(&default_interface.name)
                    .arg(gw.to_string())
                    .output()?;
                warn!(
                    "executing: route add -host {} -ifscope {} {}",
                    v4, default_interface.name, gw
                );
                if !out.status.success() {
                    let err = String::from_utf8_lossy(&out.stderr);
                    // best-effort: ignore if already exists
                    if !err.contains("File exists") {
                        warn!(
                            "failed to add host route {} via {} ifscope {}: {}",
                            v4, gw, default_interface.name, err.trim()
                        );
                    }
                }
            }
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(gw) = gateway_v6 {
                let out = std::process::Command::new("route")
                    .arg("add")
                    .arg("-inet6")
                    .arg("-host")
                    .arg(v6.to_string())
                    .arg("-ifscope")
                    .arg(&default_interface.name)
                    .arg(gw.to_string())
                    .output()?;
                warn!(
                    "executing: route add -inet6 -host {} -ifscope {} {}",
                    v6, default_interface.name, gw
                );
                if !out.status.success() {
                    let err = String::from_utf8_lossy(&out.stderr);
                    if !err.contains("File exists") {
                        warn!(
                            "failed to add ipv6 host route {} via {} ifscope {}: {}",
                            v6, gw, default_interface.name, err.trim()
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Try to delete a previously added host-specific route for a unicast destination.
/// Best-effort: ignore failures when the route is already gone.
pub(crate) fn maybe_delete_host_route_for_addr(ip: &std::net::IpAddr) -> std::io::Result<()> {
    let default_interface =
        get_outbound_interface().ok_or(new_io_error("get default interface"))?;

    match ip {
        std::net::IpAddr::V4(v4) => {
            let out = std::process::Command::new("route")
                .arg("delete")
                .arg("-host")
                .arg(v4.to_string())
                .arg("-ifscope")
                .arg(&default_interface.name)
                .output()?;
            warn!(
                "executing: route delete -host {} -ifscope {}",
                v4, default_interface.name
            );
            if !out.status.success() {
                // best-effort cleanup
                let err = String::from_utf8_lossy(&out.stderr);
                warn!(
                    "failed to delete host route {} ifscope {}: {}",
                    v4,
                    default_interface.name,
                    err.trim()
                );
            }
        }
        std::net::IpAddr::V6(v6) => {
            let out = std::process::Command::new("route")
                .arg("delete")
                .arg("-inet6")
                .arg("-host")
                .arg(v6.to_string())
                .arg("-ifscope")
                .arg(&default_interface.name)
                .output()?;
            warn!(
                "executing: route delete -inet6 -host {} -ifscope {}",
                v6, default_interface.name
            );
            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr);
                warn!(
                    "failed to delete ipv6 host route {} ifscope {}: {}",
                    v6,
                    default_interface.name,
                    err.trim()
                );
            }
        }
    }

    Ok(())
}

/// failing to delete the default route won't cause route failure
pub fn maybe_routes_clean_up(cfg: &TunConfig) -> std::io::Result<()> {
    if !cfg.route_all {
        return Ok(());
    }

    let (gateway_v4, gateway_v6) = get_default_gateway()?;
    let default_interface =
        get_outbound_interface().ok_or(new_io_error("get default interface"))?;

    let mut result = Ok(());

    // Clean up IPv4 default route
    if let Some(gateway) = gateway_v4 {
        let cmd = std::process::Command::new("route")
            .arg("delete")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("0/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route delete -ifscope {} 0/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            result = Err(new_io_error("delete default IPv4 route failed"));
        }
    }

    // Clean up IPv6 default route
    if let Some(gateway) = gateway_v6 {
        let cmd = std::process::Command::new("route")
            .arg("delete")
            .arg("-inet6")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("::/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route delete -inet6 -ifscope {} ::/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            result = Err(new_io_error("delete default IPv6 route failed"));
        }
    }

    // Try to clean up bypass routes (best-effort)
    for (cidr, kind) in [("224.0.0.0/4", "-net"), ("169.254.0.0/16", "-net")] {
        let out = std::process::Command::new("route")
            .arg("delete")
            .arg(kind)
            .arg(cidr)
            .arg("-interface")
            .arg(&default_interface.name)
            .output()?;
        if !out.status.success() {
            warn!("failed to delete IPv4 bypass route {} on {}", cidr, default_interface.name);
        }
    }
    for cidr in ["ff00::/8", "fe80::/10"] {
        let out = std::process::Command::new("route")
            .arg("delete")
            .arg("-inet6")
            .arg(cidr)
            .arg("-interface")
            .arg(&default_interface.name)
            .output()?;
        if !out.status.success() {
            warn!("failed to delete IPv6 bypass route {} on {}", cidr, default_interface.name);
        }
    }

    if gateway_v4.is_none() && gateway_v6.is_none() {
        Err(new_io_error(
            "cant delete default route, default gateway not found",
        ))
    } else {
        result
    }
}

#[derive(Debug)]
struct RouteEntry {
    dst: String,
    gateway: String,
    ifname: String,
    is_default: bool,
}

/// 解析 route 消息，提取 default route 信息
unsafe fn parse_route_message(rtm: &libc::rt_msghdr) -> Option<RouteEntry> {
    let mut sa_ptr = unsafe {
        (rtm as *const _ as *const u8).add(mem::size_of::<libc::rt_msghdr>())
    };
    let addrs = rtm.rtm_addrs;

    let mut dst = None;
    let mut gateway = None;
    let mut ifname = None;
    let mut is_default = false;

    for i in 0..libc::RTAX_MAX {
        if (addrs & (1 << i)) == 0 {
            continue;
        }

        let sa = sa_ptr as *const libc::sockaddr;
        let sa_len = unsafe { (*sa).sa_len as usize };

        match i {
            libc::RTAX_DST => {
                if unsafe { (*sa).sa_family as i32 == libc::AF_INET } {
                    let sin = unsafe { &*(sa as *const libc::sockaddr_in) };
                    let addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    dst = Some(addr.to_string());
                    if addr == Ipv4Addr::UNSPECIFIED {
                        is_default = true;
                    }
                } else if unsafe { (*sa).sa_family as i32 == libc::AF_INET6 } {
                    let sin6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
                    let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    dst = Some(addr.to_string());
                    if addr == Ipv6Addr::UNSPECIFIED {
                        is_default = true;
                    }
                }
            }
            libc::RTAX_GATEWAY => {
                if unsafe { (*sa).sa_family as i32 == libc::AF_INET } {
                    let sin = unsafe { &*(sa as *const libc::sockaddr_in) };
                    let addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    gateway = Some(addr.to_string());
                } else if unsafe { (*sa).sa_family as i32 == libc::AF_INET6 } {
                    let sin6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
                    let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    gateway = Some(addr.to_string());
                }
            }
            libc::RTAX_IFP => {
                if unsafe { (*sa).sa_family as i32 == libc::AF_LINK } {
                    let sdl = unsafe { &*(sa as *const libc::sockaddr_dl) };
                    let name = unsafe {
                        std::slice::from_raw_parts(
                            sdl.sdl_data.as_ptr() as *const u8,
                            sdl.sdl_nlen as usize,
                        )
                    };
                    if let Ok(s) = std::str::from_utf8(name) {
                        ifname = Some(s.to_string());
                    }
                }
            }
            _ => {}
        }

        // 前进到下一个 sockaddr
        sa_ptr = unsafe { sa_ptr.add(sa_len.max(mem::size_of::<libc::sockaddr>())) };
    }

    if is_default {
        Some(RouteEntry {
            dst: dst.unwrap_or_default(),
            gateway: gateway.unwrap_or_default(),
            ifname: ifname.unwrap_or_default(),
            is_default,
        })
    } else {
        None
    }
}

pub fn has_default_route(rtm: &libc::rt_msghdr) -> bool {
    let entry = unsafe { parse_route_message(rtm) };
    if entry.is_some() {
        let entry = entry.unwrap();
        warn!("Detected default route change: {:?}", entry);
        let (gateway_v4, gateway_v6) = get_default_gateway().unwrap_or((None, None));
        if let Some(gateway) = gateway_v4 {
            if gateway.to_string() == entry.gateway {
                return true;
            }
        } else if let Some(gateway) = gateway_v6 {
            if gateway.to_string() == entry.gateway {
                return true;
            }
        }
        false
    } else {
        false
    }
}
