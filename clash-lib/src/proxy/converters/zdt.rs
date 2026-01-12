use tracing::warn;

use crate::{
    Error,
    config::internal::proxy::OutboundZdt,
    proxy::{
        HandlerCommonOptions,
        transport::{TlsClient, WsClient},
        zdt::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundZdt> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundZdt) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundZdt> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundZdt) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if s.tls.unwrap_or_default() && skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }

        let tls = if s.tls.unwrap_or_default() {
            let client = TlsClient::new(
                skip_cert_verify,
                s.sni
                    .as_ref()
                    .map(|x| x.to_owned())
                    .unwrap_or(s.common_opts.server.to_owned()),
                None,
                None,
            );
            Some(Box::new(client) as _)
        } else {
            None
        };

        let transport = s
            .network
            .as_ref()
            .map(|x| match x.as_str() {
                "ws" => s
                    .ws_opts
                    .as_ref()
                    .map(|x| {
                        let client: WsClient = (x, &s.common_opts)
                            .try_into()
                            .expect("invalid ws_opts");
                        Box::new(client) as _
                    })
                    .ok_or(Error::InvalidConfig(
                        "ws_opts is required for ws".to_owned(),
                    )),
                _ => Err(Error::InvalidConfig(format!(
                    "unsupported zdt network: {x}"
                ))),
            })
            .transpose()?;

        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            security: s.security.clone(),
            key: s.key.clone(),
            salt: s.salt.clone(),
            iv: s.iv.clone(),
            udp: s.udp.unwrap_or_default(),
            tls,
            transport,
        });
        Ok(h)
    }
}
