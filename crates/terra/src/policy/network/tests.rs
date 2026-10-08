use super::describe;
use super::rules::parse_port_mappings;
use crate::config::{Network, NetworkMode, StaticDnsRecord};

fn build_network(mode: NetworkMode, allow: &[&str]) -> Network {
    Network {
        mode,
        allow: allow.iter().map(ToString::to_string).collect(),
        ..Network::default()
    }
}
fn build_dns_record(name: &str, addr: &str) -> StaticDnsRecord {
    StaticDnsRecord {
        name: name.into(),
        addr: addr.into(),
    }
}
const HOST_LOOPBACK_SYMBOL: &str = "HOST_LOOPBACK";

#[test]
fn parse_port_mappings_and_reject_invalid_entries() {
    let mappings = parse_port_mappings(&["8080".into(), "3000:80".into()]).unwrap();
    assert_eq!(mappings[0].host, 8080);
    assert_eq!(mappings[0].guest, 8080);
    assert_eq!(mappings[1].host, 3000);
    assert_eq!(mappings[1].guest, 80);
    assert!(parse_port_mappings(&["0:80".into()]).is_err()); // port 0 rejected
    assert!(parse_port_mappings(&["nope".into()]).is_err());

    // Two rules on one host port: the second bind fails mid-boot, long
    // after the recipe was approved, so the recipe is refused instead.
    let err = parse_port_mappings(&["8080".into(), "8080:90".into()])
        .unwrap_err()
        .to_string();
    assert!(err.contains("already carries"), "{err}");
    assert!(parse_port_mappings(&["8080:80".into(), "8081:80".into()]).is_ok());
    let mappings = parse_port_mappings(&["8080:80/tcp".into(), "8080:53/udp".into()]).unwrap();
    assert_eq!(
        mappings[0].transport,
        terra_protocol::network::ResourceKind::Tcp
    );
    assert_eq!(
        mappings[1].transport,
        terra_protocol::network::ResourceKind::Udp
    );
    assert_eq!(mappings[1].guest, 53);
    for ports in [
        vec!["8080/udp".into(), "8080:53/udp".into()],
        vec!["8080/sctp".into()],
        vec!["8080/udp/udp".into()],
    ] {
        assert!(parse_port_mappings(&ports).is_err());
    }

    let refused = crate::config::parse_recipe(
        "network:\n  ports: [\"8080\", \"8080:90\"]\n",
        std::path::Path::new("/proj"),
        std::path::Path::new("/proj/r.yaml"),
    )
    .unwrap_err()
    .to_string();
    assert!(refused.contains("already carries"), "{refused}");
}

#[test]
fn published_mapping_limit_counts_host_listeners_even_for_one_guest_port() {
    let mut ports = (1..=terra_protocol::MAX_PUBLISHED_PORTS)
        .map(|host| format!("{host}:80"))
        .collect::<Vec<_>>();
    assert!(parse_port_mappings(&ports).is_ok());
    ports.push("1:80/udp".into());
    let limit = format!("at most {}", terra_protocol::MAX_PUBLISHED_PORTS);
    let error = parse_port_mappings(&ports).unwrap_err();
    assert!(error.to_string().contains(&limit), "{error}");
    let yaml = format!(
        "network:\n  ports: {}",
        serde_json::to_string(&ports).unwrap()
    );
    let error = crate::config::parse_recipe(
        &yaml,
        std::path::Path::new("/proj"),
        std::path::Path::new("/proj/r.yaml"),
    )
    .unwrap_err();
    assert!(error.to_string().contains(&limit), "{error}");
}

/// The banner tells the truth about the posture - including that records
/// grant nothing, so an allowlist with only `hosts:` still lets nothing out.
#[test]
fn describe_names_the_posture() {
    let mut open = build_network(NetworkMode::UnrestrictedPublic, &[]);
    assert_eq!(describe(&open), "unrestricted-public (public egress only)");
    open.allow = vec!["10.0.0.5:5432".into()];
    assert_eq!(
        describe(&open),
        "unrestricted-public (public egress + listed rules)"
    );

    let mut closed = build_network(NetworkMode::Allowlist, &[]);
    assert!(describe(&closed).contains("not even DNS"));
    // …but a box with records has a resolver, and answering them is the
    // whole point of writing them - only what is *reachable* is nothing.
    closed.hosts = vec![build_dns_record("db.local", HOST_LOOPBACK_SYMBOL)];
    let with_records = describe(&closed);
    assert!(
        !with_records.contains("not even DNS"),
        "the records are answered: {with_records}"
    );
    assert!(
        with_records.contains("nothing is reachable"),
        "{with_records}"
    );
    closed.allow = vec!["db.local:5432".into()];
    assert_eq!(describe(&closed), "allowlist active (deny by default)");
}
