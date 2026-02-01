use crate::{
    Error, Runner,
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    config::internal::config::TunConfig,
    defer,
    proxy::tun::{
        datagram::handle_inbound_datagram,
        routes::{self},
        stream::handle_inbound_stream,
    },
};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};
use url::Url;

#[derive(Default)]
struct TunInitializationConfig {
    fd: Option<u32>,
    tun_name: Option<String>,
    #[cfg(target_os = "windows")]
    guid: Option<u128>,
}

pub fn get_runner(
    cfg: TunConfig,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
) -> Result<Option<Runner>, Error> {
    if !cfg.enable {
        trace!("tun is disabled");
        return Ok(None);
    }

    let mut tun_init_config = TunInitializationConfig::default();
    match Url::parse(&cfg.device_id) {
        Ok(u) => match u.scheme() {
            "fd" => {
                let fd = u
                    .host()
                    .expect("tun fd must be provided")
                    .to_string()
                    .parse()
                    .map_err(|x| Error::InvalidConfig(format!("tun fd {x}")))?;
                tun_init_config.fd = Some(fd);
            }
            "dev" => {
                let dev = u.host().expect("tun dev must be provided").to_string();
                if cfg!(target_os = "macos") && !dev.starts_with("utun") {
                    return Err(Error::InvalidConfig(format!(
                        "invalid device id: {}. tun name must be utunX",
                        cfg.device_id
                    )));
                }
                tun_init_config.tun_name = Some(dev);
                #[cfg(target_os = "windows")]
                {
                    let guid = u.query_pairs().find(|(k, _)| k == "guid");
                    if let Some((_, v)) = guid {
                        let guid = uuid::Uuid::parse_str(&v).map_err(|x| {
                            Error::InvalidConfig(format!("invalid guid: {x}"))
                        })?;
                        tun_init_config.guid = Some(guid.as_u128());
                    }
                }
            }
            _ => {
                return Err(Error::InvalidConfig(format!(
                    "invalid device id: {}",
                    cfg.device_id
                )));
            }
        },
        Err(_) => {
            if cfg!(target_os = "macos") && !&cfg.device_id.starts_with("utun") {
                return Err(Error::InvalidConfig(format!(
                    "invalid device id: {}. tun name must be utunX",
                    cfg.device_id
                )));
            }
            tun_init_config.tun_name = Some(cfg.device_id.clone());
        }
    };

    let tun = if let Some(fd) = tun_init_config.fd {
        #[cfg(target_family = "unix")]
        {
            info!("tun started with fd {}", fd);
            unsafe { tun_rs::AsyncDevice::from_fd(fd as _)? }
        }

        #[cfg(not(target_family = "unix"))]
        {
            return Err(Error::InvalidConfig(format!(
                "tun fd({fd}) is only supported on Unix-like systems"
            )));
        }
    } else {
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            use crate::proxy::tun::routes::maybe_add_routes;
            use network_interface::NetworkInterfaceConfig;
            use tun_rs::DeviceBuilder;

            let tun_name =
                tun_init_config.tun_name.expect("tun name must be provided");
            let tun_exist = network_interface::NetworkInterface::show()
                .map(|ifs| ifs.into_iter().any(|x| x.name == tun_name))
                .unwrap_or_default();

            if tun_exist {
                info!("tun device {} already exists, using it.", &tun_name);
            } else {
                info!("tun device {} does not exist, creating.", &tun_name);
            }

            let mut tun_builder = DeviceBuilder::new();
            tun_builder = tun_builder.name(&tun_name).mtu(
                cfg.mtu
                    .unwrap_or(if cfg!(windows) { 65535u16 } else { 1500u16 }),
            );

            if !tun_exist {
                debug!("setting tun ipv4 addr: {:?}", cfg.gateway);
                tun_builder = tun_builder.ipv4(
                    cfg.gateway.addr(),
                    cfg.gateway.netmask(),
                    None,
                );

                if let Some(gateway_v6) = cfg.gateway_v6 {
                    debug!("setting tun ipv6 addr: {:?}", cfg.gateway_v6);
                    tun_builder =
                        tun_builder.ipv6(gateway_v6.addr(), gateway_v6.netmask());
                }
            }
            #[cfg(target_os = "windows")]
            if let Some(guid) = tun_init_config.guid {
                tun_builder = tun_builder.device_guid(guid);
            }

            let dev = tun_builder.build_async()?;

            if !tun_exist {
                info!("setting up routes for tun {}", &tun_name);
                maybe_add_routes(&cfg, &tun_name)?;
            } else {
                info!("skipping route setup for existing tun {}", &tun_name);
            }

            dev
        }
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
            return Err(Error::InvalidConfig(
                "only fd is supported on mobile platforms".to_string(),
            ));
        }
    };

    let (stack, mut tcp_listener, udp_socket) = watfaq_netstack::NetStack::new();

    // On macOS, we temporarily pause writes to utun after a route/default gateway change
    // to avoid overwhelming the kernel mbuf pool (mbuf_watchdog panic) during Wi‑Fi
    // switches or wake-from-sleep transitions.
    #[cfg(target_os = "macos")]
    let mut netchange_rx = routes::subscribe_netchange();
    #[cfg(target_os = "macos")]
    let tun_paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(target_os = "macos")]
    {
        let tun_paused_clone = tun_paused.clone();
        // Debounced pause controller: any netchange will (re)set a 3s pause window.
        tokio::spawn(async move {
            use tokio::time::{Duration, Instant};
            // Use a single pinned Sleep we can reset, avoiding borrow/await issues.
            let mut delay = Box::pin(tokio::time::sleep(Duration::from_secs(365 * 24 * 60 * 60)));
            loop {
                tokio::select! {
                    biased;
                    // When the timer fires, resume writes and push the timer far in the future.
                    _ = &mut delay => {
                        // Pause window elapsed; resume writes
                        tun_paused_clone.store(false, std::sync::atomic::Ordering::SeqCst);
                        warn!("netchange pause window ended; resuming utun writes");
                        // Re-arm timer to a far-future deadline (effectively disabled)
                        delay.as_mut().reset(Instant::now() + Duration::from_secs(365 * 24 * 60 * 60));
                    }
                    res = netchange_rx.recv() => {
                        match res {
                            Ok(_) => {
                                // Start or extend the pause window to 3s
                                let already_paused = tun_paused_clone.load(std::sync::atomic::Ordering::SeqCst);
                                tun_paused_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                                if already_paused {
                                    trace!("netchange detected; extending utun write pause window (3s)");
                                } else {
                                    warn!("netchange detected; pausing utun writes for 3s to protect mbufs");
                                }
                                // Reset timer to fire in 3 seconds (debounce)
                                delay.as_mut().reset(Instant::now() + Duration::from_secs(3));
                            }
                            Err(_) => {
                                // broadcaster dropped; nothing more to do
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    Ok(Some(Box::pin(async move {
        defer! {
            warn!("cleaning up routes");

            match routes::maybe_routes_clean_up(&cfg) {
                Ok(_) => {}
                Err(e) => {
                    error!("failed to clean up routes: {}", e);
                }
            }

            #[cfg(target_os = "macos")]
            {
                // Also remove any host routes we added for DNS servers, etc.
                routes::cleanup_host_routes();
            }
        }

        let so_mark = cfg.so_mark;

        let framed = tun_rs::async_framed::DeviceFramed::new(
            tun,
            tun_rs::async_framed::BytesCodec::new(),
        );

        let (mut tun_sink, mut tun_stream) = framed.split::<bytes::Bytes>();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let mut futs: Vec<Runner> = vec![];

        // dispatcher -> stack -> tun
        futs.push(Box::pin(async move {
            while let Some(pkt) = stack_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        #[cfg(target_os = "macos")]
                        {
                            if tun_paused.load(std::sync::atomic::Ordering::SeqCst) {
                                // Drop packets during pause window to avoid filling utun ifq/mbufs
                                trace!("dropping packet due to netchange pause window");
                                continue;
                            }
                        }
                        if let Err(e) = tun_sink.send(pkt.into_bytes()).await {
                            error!("failed to send pkt to tun: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("tun stack error: {}", e);
                        break;
                    }
                }
            }

            Err(Error::Operation("tun stopped unexpectedly 0".to_string()))
        }));

        // tun -> stack -> dispatcher
        futs.push(Box::pin(async move {
            while let Some(pkt) = tun_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) =
                            stack_sink.send(watfaq_netstack::Packet::new(pkt)).await
                        {
                            error!("failed to send pkt to stack: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("tun stream error: {}", e);
                        break;
                    }
                }
            }

            Err(Error::Operation("tun stopped unexpectedly 1".to_string()))
        }));

        let dsp = dispatcher.clone();
        futs.push(Box::pin(async move {
            while let Some(stream) = tcp_listener.next().await {
                debug!(
                    "new tun TCP connection: {} -> {}",
                    stream.local_addr(),
                    stream.remote_addr()
                );

                tokio::spawn(handle_inbound_stream(stream, dsp.clone(), so_mark));
            }

            Err(Error::Operation("tun stopped unexpectedly 2".to_string()))
        }));

        futs.push(Box::pin(async move {
            handle_inbound_datagram(
                udp_socket,
                dispatcher,
                resolver,
                so_mark,
                cfg.dns_hijack,
            )
            .await;
            Err(Error::Operation("tun stopped unexpectedly 3".to_string()))
        }));

        futures::future::select_all(futs).await.0.map_err(|x| {
            error!("tun error: {}. stopped", x);
            x
        })
    })))
}
