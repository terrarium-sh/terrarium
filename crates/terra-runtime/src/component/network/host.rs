//! Broker authority for the combined network/device frontend.

pub struct NetworkHost {
    broker: Option<terra_network::Client>,
    pub(super) listener_grants: Vec<terra_network::config::PublishedListener>,
    denial_diagnostics: DenialDiagnostics,
}

#[derive(Default)]
struct DenialDiagnostics {
    emitted: u8,
}

impl DenialDiagnostics {
    fn format_next(&mut self, target: &str, is_name_lookup: bool) -> Option<String> {
        if self.emitted == 64 {
            return None;
        }
        self.emitted += 1;
        let target = target
            .escape_debug()
            .take(terra_protocol::network::MAX_NETWORK_NAME_BYTES)
            .collect::<String>();
        let reason = if is_name_lookup {
            "name lookup"
        } else {
            "access"
        };
        Some(format!("egress: blocked {target} - policy denied {reason}"))
    }
}

#[derive(Clone)]
pub struct NetworkBackend {
    pub client: terra_network::Client,
    pub ready: terra_network::config::Ready,
    pub listeners: Vec<terra_network::config::PublishedListener>,
}

impl NetworkBackend {
    pub(crate) fn host_service_ports(&self) -> &[Option<u16>] {
        &self.ready.host_service_ports
    }
}

impl NetworkHost {
    #[must_use]
    pub fn new(backend: Option<NetworkBackend>) -> Self {
        let (broker, listener_grants) = match backend {
            Some(backend) => (Some(backend.client), backend.listeners),
            None => (None, Vec::new()),
        };
        Self {
            broker,
            listener_grants,
            denial_diagnostics: DenialDiagnostics::default(),
        }
    }

    pub(super) fn clone_broker_client(
        &self,
    ) -> Result<terra_network::Client, terra_network::Error> {
        self.broker.clone().ok_or(terra_network::Error::Closed)
    }

    pub(crate) fn disconnect(&self) {
        if let Some(broker) = &self.broker {
            broker.disconnect();
        }
    }

    pub(super) fn report_denial(&mut self, target: &str, is_name_lookup: bool) {
        if let Some(message) = self.denial_diagnostics.format_next(target, is_name_lookup) {
            log::warn!("terra: {message}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DenialDiagnostics;

    #[test]
    fn denial_diagnostics_escape_targets_and_stop_after_sixty_four_events() {
        let mut diagnostics = DenialDiagnostics::default();
        assert_eq!(
            diagnostics
                .format_next("169.254.169.254:80", false)
                .as_deref(),
            Some("egress: blocked 169.254.169.254:80 - policy denied access")
        );
        let target = "\ninjected".repeat(1000);
        let message = diagnostics.format_next(&target, true).unwrap();
        assert!(!message.contains('\n'));
        assert!(message.contains("\\ninjected"));
        assert!(message.len() < 512);
        for _ in 2..64 {
            assert!(diagnostics.format_next("203.0.113.1:443", false).is_some());
        }
        for _ in 0..128 {
            assert_eq!(diagnostics.format_next("169.254.169.254:80", false), None);
        }
        assert_eq!(diagnostics.emitted, 64);
    }
}
