use std::sync::Arc;

use tracing::debug;

use crate::{
    app::dispatcher::Dispatcher,
    session::{Network, Session, Type},
};
#[cfg(not(target_os = "ios"))]
use crate::app::net::DEFAULT_OUTBOUND_INTERFACE;

pub(crate) async fn handle_inbound_stream(
    stream: watfaq_netstack::TcpStream,

    dispatcher: Arc<Dispatcher>,
    so_mark: Option<u32>,
) {
    // On iOS, skip interface binding — NEPacketTunnelProvider automatically
    // routes the extension's connections through the physical interface.
    #[cfg(target_os = "ios")]
    let tun_iface = None;
    #[cfg(not(target_os = "ios"))]
    let tun_iface = DEFAULT_OUTBOUND_INTERFACE
        .read()
        .await
        .clone()
        .inspect(|x| {
            debug!(
                "selecting outbound interface: {:?} for tun TCP connection",
                x
            );
        });

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Tun,
        source: stream.local_addr(),
        destination: stream.remote_addr().into(),
        iface: tun_iface,
        so_mark,
        ..Default::default()
    };

    debug!("new tun TCP session assigned: {}", sess);
    dispatcher.dispatch_stream(sess, Box::new(stream)).await;
}
