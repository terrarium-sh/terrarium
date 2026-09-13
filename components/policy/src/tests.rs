use super::rules::*;
use super::runtime::{BoxPolicy, LEARNED_ADDRESSES_CAPACITY};
use crate::config::{Network, NetworkMode, StaticDnsRecord};
use std::net::IpAddr;
use terra_network::{GuestNetworkConfig, NameLookup, Policy};

fn gateway_addresses() -> [IpAddr; 2] {
    GuestNetworkConfig::default().gateway_addresses()
}

fn build_network(mode: NetworkMode, allow: &[&str]) -> Network {
    Network {
        mode,
        allow: allow.iter().map(ToString::to_string).collect(),
        hosts: vec![],
        host_addresses: vec![],
    }
}

fn build_policy(network: &Network) -> Result<BoxPolicy, String> {
    BoxPolicy::new(network)
}

fn build_box_policy(mode: NetworkMode, allow: &[&str]) -> BoxPolicy {
    build_policy(&build_network(mode, allow)).expect("test policy")
}

/// One `hosts:` record. `addr` is an address or the host token.
fn build_dns_record(name: &str, addr: &str) -> StaticDnsRecord {
    StaticDnsRecord {
        name: name.into(),
        addr: addr.into(),
    }
}

/// A policy with both halves: records, and the rules that open them.
fn build_published_policy(
    mode: NetworkMode,
    hosts: &[StaticDnsRecord],
    allow: &[&str],
) -> BoxPolicy {
    let mut network = build_network(mode, allow);
    network.hosts = hosts.to_vec();
    build_policy(&network).expect("test policy")
}

fn format_build_error(network: &Network) -> String {
    build_policy(network)
        .expect_err("this network section must not build")
        .clone()
}

/// An `allow:` rule is respected whatever the floor thinks - that is the
/// point of writing one. The floor is for what *nobody* wrote down.
#[test]
fn an_allow_rule_outranks_the_floor() {
    for mode in [NetworkMode::Allowlist, NetworkMode::UnrestrictedPublic] {
        // A single address, on the port it named and nothing else nearby.
        let one = build_box_policy(mode, &["10.0.0.5:5432"]);
        assert!(
            one.allows("10.0.0.5".parse().unwrap(), Some(5432)),
            "{mode:?}"
        );
        assert!(
            !one.allows("10.0.0.5".parse().unwrap(), Some(22)),
            "{mode:?}"
        );
        assert!(
            !one.allows("10.0.0.6".parse().unwrap(), Some(5432)),
            "{mode:?}"
        );
        for held in ["127.0.0.1", "169.254.169.254", "224.0.0.251"] {
            assert!(
                !one.allows(held.parse().unwrap(), Some(5432)),
                "{mode:?} {held}"
            );
        }

        // A range is a rule too: the LAN, the loopback and even multicast
        // are reachable when the recipe says so.
        let lan = build_box_policy(mode, &["10.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4"]);
        assert!(
            lan.allows("10.0.0.6".parse().unwrap(), Some(22)),
            "{mode:?}"
        );
        assert!(
            lan.allows("127.0.0.1".parse().unwrap(), Some(5432)),
            "{mode:?}"
        );
        assert!(
            lan.allows("224.0.0.251".parse().unwrap(), Some(1900)),
            "{mode:?}"
        );
        assert!(
            !lan.allows("169.254.169.254".parse().unwrap(), Some(80)),
            "{mode:?}"
        );
    }
}

/// With nothing written down, the widest mode is *public* egress: the floor
/// is what makes that claim true.
#[test]
fn nothing_unwritten_crosses_the_floor() {
    let open = build_box_policy(NetworkMode::UnrestrictedPublic, &[]);
    for held in [
        "127.0.0.1",
        "169.254.169.254",
        "10.0.0.5",
        "192.168.1.1",
        "100.96.0.1",
        "239.255.255.250",
        "ff02::1",
        // …including the IPv4-mapped multicast spelling, which
        // `Ipv6Addr::is_multicast` answers `false` for on its own.
        "::ffff:239.255.255.250",
    ] {
        assert!(
            !open.allows(held.parse().unwrap(), Some(443)),
            "{held} must be floored"
        );
    }
    assert!(open.allows("1.1.1.1".parse().unwrap(), Some(443)));

    // The allowlist reaches nothing at all without a rule - not even names.
    let closed = build_policy(&Network::default()).unwrap();
    assert!(!closed.allows("1.1.1.1".parse().unwrap(), Some(443)));
    assert!(matches!(
        closed.lookup_name("example.com"),
        NameLookup::Denied
    ));
}

#[test]
fn host_interface_addresses_need_an_explicit_address_rule() {
    let address: IpAddr = "1.1.1.1".parse().unwrap();
    let mut network = build_network(NetworkMode::UnrestrictedPublic, &[]);
    network.host_addresses = vec![address.to_string()];
    let blocked = build_policy(&network).unwrap();
    assert!(!blocked.allows(address, Some(443)));
    assert_eq!(
        blocked.accept_resolved("anything.test", &[address]),
        [] as [std::net::IpAddr; 0]
    );

    network.allow.push("1.1.1.1:443".into());
    let allowed = build_policy(&network).unwrap();
    assert!(allowed.allows(address, Some(443)));
    assert!(!allowed.allows(address, Some(80)));
}

#[test]
fn nat64_cannot_reach_a_host_interface_address() {
    let address: IpAddr = "1.1.1.1".parse().unwrap();
    let mapped: IpAddr = "64:ff9b::1.1.1.1".parse().unwrap();
    let mut network = build_network(NetworkMode::UnrestrictedPublic, &[]);
    network.host_addresses = vec![address.to_string()];
    let policy = build_policy(&network).unwrap();
    assert!(!policy.allows(mapped, Some(443)));
    assert_eq!(
        policy.accept_resolved("anything.test", &[mapped]),
        [] as [std::net::IpAddr; 0]
    );
}

/// One allowlist box driven only through the [`Policy`] trait, as the
/// gateway drives it: resolve, learn from the answer bytes, then connect.
#[test]
fn allowlist_name_lookup_learns_only_granted_public_addresses() {
    let p = build_published_policy(
        NetworkMode::Allowlist,
        &[
            build_dns_record("db.local", HOST_LOOPBACK_SYMBOL),
            build_dns_record("nas.local", "10.0.0.5"),
        ],
        &["api.test:443", "db.local:5432", "nas.local:445"],
    );
    assert!(matches!(
        p.lookup_name("db.local"),
        NameLookup::Static(addresses) if addresses == gateway_addresses()
    ));
    assert!(matches!(p.lookup_name("api.test"), NameLookup::Resolve));
    let ip: IpAddr = "93.184.216.34".parse().unwrap();
    assert_eq!(p.accept_resolved("api.test", &[ip]), [ip]);
    assert!(p.allows(ip, Some(443)));
    assert!(!p.allows(ip, Some(80)));

    // An ungranted name teaches nothing.
    let other: IpAddr = "5.5.5.5".parse().unwrap();
    assert_eq!(
        p.accept_resolved("evil.test", &[other]),
        [] as [std::net::IpAddr; 0]
    );
    assert!(!p.allows(other, Some(443)));

    // The network adapter dials the host on loopback, so the policy grants
    // it through the separate host-service capability rather than its gateway address.
    assert_eq!(p.host_service_ports(), [Some(5432), Some(5432)]);
    assert!(!p.allows(gateway_addresses()[0], Some(5432)));
    let nas: IpAddr = "10.0.0.5".parse().unwrap();
    assert!(p.allows(nas, Some(445)));

    assert!(matches!(p.lookup_name("exfil.example"), NameLookup::Denied));
    assert!(!p.allows("1.1.1.1".parse().unwrap(), Some(443)));
}

/// The same lifecycle under `unrestricted-public`: public egress needs no
/// rules; the floor and the host still do.
#[test]
fn unrestricted_public_name_lookup_keeps_the_floor_closed() {
    let p = build_published_policy(
        NetworkMode::UnrestrictedPublic,
        &[build_dns_record("db.local", HOST_LOOPBACK_SYMBOL)],
        &["db.local:5432", "10.0.0.5:445"],
    );
    assert!(matches!(p.lookup_name("db.local"), NameLookup::Static(_)));
    assert!(matches!(
        p.lookup_name("anything.test"),
        NameLookup::Resolve
    ));

    // Public is open by default; the floor and the host are not.
    assert!(p.allows("1.1.1.1".parse().unwrap(), Some(443)));
    assert!(!p.allows("192.168.1.1".parse().unwrap(), Some(443)));
    assert!(!p.allows(gateway_addresses()[0], Some(22)));
    let public: IpAddr = "1.1.1.1".parse().unwrap();
    assert_eq!(p.accept_resolved("anything.test", &[public]), [public]);
    assert_eq!(
        p.accept_resolved("anything.test", &["192.168.1.1".parse().unwrap()]),
        [] as [std::net::IpAddr; 0]
    );
    assert_eq!(
        p.accept_resolved("anything.test", &["::ffff:127.0.0.1".parse().unwrap()]),
        [] as [std::net::IpAddr; 0]
    );

    // The host capability and written address across the floor remain scoped.
    assert_eq!(p.host_service_ports(), [Some(5432), Some(5432)]);
    assert!(!p.allows(gateway_addresses()[0], Some(5432)));
    assert!(p.allows("10.0.0.5".parse().unwrap(), Some(445)));
}

/// The four routes a query can take - each a decision about whether a name,
/// and so the data in it, leaves the box.
#[test]
fn name_lookup_is_static_resolved_or_denied() {
    let mut network = build_network(NetworkMode::Allowlist, &["api.test:443"]);
    network.hosts = vec![build_dns_record("db.local", HOST_LOOPBACK_SYMBOL)];
    let p = build_policy(&network).unwrap();

    assert!(matches!(p.lookup_name("db.local"), NameLookup::Static(_)));
    assert!(matches!(p.lookup_name("api.test"), NameLookup::Resolve));
    for denied in ["v2.api.test", "payload.db.local", "exfil.example"] {
        assert!(
            matches!(p.lookup_name(denied), NameLookup::Denied),
            "{denied}"
        );
    }

    let open = build_box_policy(NetworkMode::UnrestrictedPublic, &[]);
    assert!(matches!(
        open.lookup_name("anything.test"),
        NameLookup::Resolve
    ));

    // An address rule does not turn that gate exclusive - it is read there,
    // it simply has nothing to say about resolution.
    assert!(
        build_box_policy(NetworkMode::UnrestrictedPublic, &["10.0.0.5:5432"]).forwards("any.test")
    );
    // Nor does a name rule that a `hosts:` record gave something to open;
    // a name rule with no record behind it is refused outright (see
    // [`a_name_rule_that_could_not_grant_anything_is_refused_not_ignored`]).
    assert!(
        build_published_policy(
            NetworkMode::UnrestrictedPublic,
            &[build_dns_record("nas.local", "10.0.0.5")],
            &["nas.local:445"],
        )
        .forwards("any.test")
    );
}

/// A name rule under `unrestricted-public` can only ever open what it
/// resolves at construction: public addresses are already reachable, and a
/// *learned* address cannot cross the floor. So `allow: [nas.local:445]`
/// used to sit in a recipe granting nothing while the banner read "public
/// egress + listed rules"; it is refused now, with the spellings that work.
#[test]
fn a_name_rule_that_could_not_grant_anything_is_refused_not_ignored() {
    let nas: IpAddr = "10.0.0.5".parse().unwrap();

    let err = format_build_error(&build_network(
        NetworkMode::UnrestrictedPublic,
        &["nas.local:445"],
    ));
    assert!(err.contains("opens nothing"), "{err}");
    // The message has to carry the way out, or it is just a wall.
    assert!(err.contains("hosts:"), "{err}");
    assert!(err.contains("allowlist"), "{err}");

    // The two spellings it names both work, in that same mode.
    let by_addr = build_box_policy(NetworkMode::UnrestrictedPublic, &["10.0.0.5:445"]);
    assert!(by_addr.allows(nas, Some(445)));
    assert!(!by_addr.allows(nas, Some(22)));

    let by_record = build_published_policy(
        NetworkMode::UnrestrictedPublic,
        &[build_dns_record("nas.local", "10.0.0.5")],
        &["nas.local:445"],
    );
    assert!(by_record.allows(nas, Some(445)));
    assert!(!by_record.allows(nas, Some(22)));

    // …and the same rule keeps its ordinary meaning under an allowlist,
    // where it gates public egress rather than opening the floor.
    let gated = build_box_policy(NetworkMode::Allowlist, &["api.test:443"]);
    let public: IpAddr = "93.184.216.34".parse().unwrap();
    gated.learn_named("api.test", &[(public, 300)]);
    assert!(gated.allows(public, Some(443)));
    // Even there, a name cannot reach the floor by resolving into it.
    gated.learn_named("api.test", &[(nas, 300)]);
    assert!(!gated.allows(nas, Some(443)));
}

/// The port written against a *name* binds whatever that name resolves to -
/// which is the only way a name rule can be port-scoped at all.
#[test]
fn a_learned_address_carries_its_name_s_port() {
    let p = build_box_policy(NetworkMode::Allowlist, &["api.test:443", "open.test"]);
    let resolved: IpAddr = "93.184.216.34".parse().unwrap();

    assert!(!p.allows(resolved, Some(443)), "nothing is learned yet");
    p.learn_named("api.test", &[(resolved, 300)]);
    assert!(p.allows(resolved, Some(443)));
    assert!(!p.allows(resolved, Some(80)));
    assert!(
        !p.allows(resolved, None),
        "portless flows need an any-port rule"
    );

    // The same address under a second name keeps both grants.
    p.learn_named("open.test", &[(resolved, 300)]);
    assert!(p.allows(resolved, Some(80)));

    // A name no rule covers learns nothing, however the answer arrives.
    let other: IpAddr = "5.5.5.5".parse().unwrap();
    p.learn_named("evil.test", &[(other, 300)]);
    assert!(!p.allows(other, Some(443)));
}

/// The learned set is the one thing here a guest can grow: it owns the DNS
/// for any name its own rules cover, and every answer is an entry that
/// outlives the query by up to a minute. Cache eviction bounds retained answers
/// independently of the component linear-memory limit.
#[test]
fn what_a_guest_can_teach_this_policy_is_bounded() {
    let p = build_box_policy(NetworkMode::Allowlist, &["*.attacker.test"]);
    for i in 0..(LEARNED_ADDRESSES_CAPACITY * 2) {
        let ip: IpAddr = format!("8.{}.{}.{}", (i / 65_536) % 256, (i / 256) % 256, i % 256)
            .parse()
            .unwrap();
        p.learn_named(&format!("n{i}.attacker.test"), &[(ip, 3600)]);
    }
    let held = p.learned_dns.lock().unwrap().len();
    assert!(
        held <= LEARNED_ADDRESSES_CAPACITY,
        "{held} learned entries, cap {LEARNED_ADDRESSES_CAPACITY}"
    );

    // New answers remain usable after the cache reaches capacity.
    let keeper: IpAddr = "9.9.9.7".parse().unwrap();
    p.learn_named("keep.attacker.test", &[(keeper, 3600)]);
    assert!(p.allows(keeper, Some(443)));
}

/// DNS rebinding: the answer is attacker-controlled, so it is the one place
/// a floored address could be smuggled in behind a name that was
/// legitimately allowed. An answer is not a rule, so the floor holds.
#[test]
fn an_answer_cannot_smuggle_in_a_floored_address_or_a_published_addr() {
    let p = build_published_policy(
        NetworkMode::Allowlist,
        &[build_dns_record("db.local", HOST_LOOPBACK_SYMBOL)],
        &["api.test", "db.local:5432"],
    );

    for hostile in ["10.0.0.5", "127.0.0.1", "169.254.169.254", "100.96.0.1"] {
        let ip: IpAddr = hostile.parse().unwrap();
        p.learn_named("api.test", &[(ip, 300)]);
        assert!(!p.allows(ip, Some(443)), "rebound onto {hostile}");
        assert!(!p.allows(ip, Some(22)), "rebound onto {hostile}");
    }
    assert_eq!(p.host_service_ports(), [Some(5432), Some(5432)]);
}

/// Gateway addresses are never policy grants. `HOST_LOOPBACK` passes its
/// separate service capability to the adapter, which rewrites it to loopback.
#[test]
fn only_a_host_rule_grants_the_adapter_loopback_services() {
    for mode in [NetworkMode::Allowlist, NetworkMode::UnrestrictedPublic] {
        for host in gateway_addresses().iter().copied() {
            for entry in [&[][..], &["0.0.0.0/0", "::/0"]] {
                let p = build_box_policy(mode, entry);
                assert!(!p.allows(host, Some(22)), "{mode:?} {host} {entry:?}");
                assert!(!p.allows(host, None), "{mode:?} {host} {entry:?}");
            }

            // The token is not an egress grant for the raw gateway.
            let scoped = build_box_policy(mode, &["HOST_LOOPBACK:5432"]);
            assert!(!scoped.allows(host, Some(5432)), "{mode:?} {host}");
            assert!(!scoped.allows(host, Some(22)), "{mode:?} {host}");
            assert_eq!(scoped.host_service_ports(), [Some(5432)]);

            // Portless grants every adapter loopback port.
            let open = build_box_policy(mode, &["host_loopback"]);
            assert!(!open.allows(host, Some(22)), "{mode:?} {host}");
            assert_eq!(open.host_service_ports(), [None]);
        }

        // A record resolving to the host answers with it and grants
        // nothing by itself.
        let dns_only = build_published_policy(
            mode,
            &[build_dns_record("db.local", HOST_LOOPBACK_SYMBOL)],
            &[],
        );
        assert_eq!(
            dns_only.static_answer("db.local"),
            Some(gateway_addresses().as_slice()),
            "{mode:?}"
        );
        assert!(
            !dns_only.allows(gateway_addresses()[0], Some(5432)),
            "{mode:?}"
        );
    }
}

/// An `allow:` rule spelling out the gateway's own address is refused with
/// the spelling that grants the adapter's loopback; a range keeps its meaning.
#[test]
fn an_address_rule_naming_the_gateway_is_refused_not_left_inert() {
    for mode in [NetworkMode::Allowlist, NetworkMode::UnrestrictedPublic] {
        for gw in gateway_addresses() {
            // An un-bracketed v6 ending in `:port` reads as ambiguous and
            // is refused before the rule ever classifies.
            let bare = match gw {
                IpAddr::V6(_) => format!("[{gw}]"),
                IpAddr::V4(_) => gw.to_string(),
            };
            let err = format_build_error(&build_network(mode, &[bare.as_str()]));
            assert!(err.contains(HOST_LOOPBACK_SYMBOL), "{mode:?} {gw}: {err}");

            let ported = format!("[{gw}]:80");
            let err = format_build_error(&build_network(mode, &[ported.as_str()]));
            assert!(err.contains(HOST_LOOPBACK_SYMBOL), "{mode:?} {gw}: {err}");
        }

        // The gateway's own /24, as a range: accepted, and still closed at
        // the gateway itself.
        let subnet = format!("{}/24", gateway_addresses()[0]);
        let p = build_box_policy(mode, &[subnet.as_str()]);
        assert!(!p.allows(gateway_addresses()[0], Some(80)), "{mode:?}");
    }
}

/// A record pointing at a real address is answered with it, grants nothing
/// by itself, and is opened by a rule naming it either way.
#[test]
fn a_record_can_point_at_the_lan() {
    let nas: IpAddr = "10.0.0.5".parse().unwrap();
    for mode in [NetworkMode::Allowlist, NetworkMode::UnrestrictedPublic] {
        let records = [build_dns_record("nas.local", "10.0.0.5")];

        let dns_only = build_published_policy(mode, &records, &[]);
        assert_eq!(
            dns_only.static_answer("nas.local"),
            Some([nas].as_slice()),
            "{mode:?}"
        );
        // Under the floor until something opens it, record or no record.
        assert!(!dns_only.allows(nas, Some(445)), "{mode:?}");

        // The name rule and the address rule open the same thing.
        for rule in ["nas.local:445", "10.0.0.5:445"] {
            let p = build_published_policy(mode, &records, &[rule]);
            assert!(p.allows(nas, Some(445)), "{mode:?} {rule}");
            assert!(!p.allows(nas, Some(22)), "{mode:?} {rule}");
        }
    }
}

/// Records sharing an address share what is opened there - one name's rule
/// reaches the other's service, as anywhere else in DNS.
#[test]
fn records_sharing_an_address_share_its_grants() {
    let p = build_published_policy(
        NetworkMode::Allowlist,
        &[
            build_dns_record("db.local", HOST_LOOPBACK_SYMBOL),
            build_dns_record("cache.local", HOST_LOOPBACK_SYMBOL),
        ],
        &["db.local:5432", "cache.local:6379"],
    );
    assert_eq!(p.static_answer("db.local"), p.static_answer("cache.local"));
    assert_eq!(
        p.host_service_ports(),
        [Some(5432), Some(5432), Some(6379), Some(6379)]
    );
    assert!(!p.allows(gateway_addresses()[0], Some(5432)));
    assert!(!p.allows(gateway_addresses()[0], Some(6379)));
}

/// A record is answered by the gateway, never forwarded, so nothing under
/// its name resolves either: `<base32-payload>.api.mycorp.dev` used to be
/// an outbound channel out of a box with no egress.
#[test]
fn a_record_does_not_open_dns_forwarding_for_its_subdomains() {
    let p = build_published_policy(
        NetworkMode::Allowlist,
        &[build_dns_record("api.mycorp.dev", HOST_LOOPBACK_SYMBOL)],
        &["api.mycorp.dev:8080"],
    );
    for under in [
        "payload.api.mycorp.dev",
        "a.b.api.mycorp.dev",
        "mycorp.dev",
        "anything.test",
    ] {
        assert!(!p.forwards(under), "{under} must not resolve");
    }
    assert!(!p.forwards("api.mycorp.dev"));

    // A `*.` rule covering a record opens the record *and* keeps its usual
    // meaning for the rest of the subtree, which still goes upstream.
    let sub = build_published_policy(
        NetworkMode::Allowlist,
        &[build_dns_record("api.example.com", HOST_LOOPBACK_SYMBOL)],
        &["*.example.com:8080"],
    );
    assert_eq!(sub.host_service_ports(), [Some(8080), Some(8080)]);
    assert!(!sub.allows(gateway_addresses()[0], Some(8080)));
    assert!(sub.forwards("www.example.com"));
    assert!(!sub.forwards("api.example.com"), "answered here");
}

/// A name is exactly that name; the subtree is opted into with `*.`.
/// The old behaviour handed a recipe the whole subtree whether it wanted
/// one or not, which left "only this host" unwriteable.
#[test]
fn a_name_is_exact_and_the_subtree_is_opted_into() {
    let exact = build_box_policy(NetworkMode::Allowlist, &["example.com"]);
    assert!(exact.forwards("example.com"));
    for denied in ["www.example.com", "a.b.example.com", "notexample.com"] {
        assert!(!exact.forwards(denied), "{denied} is not example.com");
    }

    let sub = build_box_policy(NetworkMode::Allowlist, &["*.example.com"]);
    for allowed in ["www.example.com", "a.b.example.com"] {
        assert!(sub.forwards(allowed), "{allowed}");
    }
    for denied in ["example.com", "notexample.com", "example.com.evil.com"] {
        assert!(!sub.forwards(denied), "{denied}");
    }
    // The matcher itself, where a suffix test would open `notexample.com`
    // to a rule meaning `example.com`.
    assert!(!name_covers("*.example.com", ".example.com"), "empty label");
    assert!(!name_covers("*.example.com", "com"));

    // Both, if a recipe wants both.
    let both = build_box_policy(NetworkMode::Allowlist, &["example.com", "*.example.com"]);
    assert!(both.forwards("example.com"));
    assert!(both.forwards("www.example.com"));

    // A leading `*.` is the only wildcard there is.
    for bad in ["*", "*.", "api.*.com", "*example.com", "*.*.example.com"] {
        let err = parse_allow(bad).unwrap_err().clone();
        assert!(err.contains("only wildcard"), "{bad}: {err}");
    }
    // …and it survives the port suffix and the normalization the rule is
    // matched by, which the query has already been through too.
    let name_of = |e: &str| match parse_allow(e).unwrap() {
        Rule::Name(name, _) => name,
        other => panic!("{e} should be a name rule: {other:?}"),
    };
    assert_eq!(name_of("*.API.test:443"), "*.api.test");
    assert!(build_box_policy(NetworkMode::Allowlist, &["*.api.test:443"]).forwards("v2.api.test"));
    assert_eq!(name_of(" example.com "), "example.com");
}

/// A `:PORT` suffix narrows the rule to that port, whatever it names.
#[test]
fn port_scope_is_enforced() {
    let ip: IpAddr = "8.8.8.3".parse().unwrap();
    let scoped = build_box_policy(NetworkMode::Allowlist, &["8.8.8.0/24:443"]);
    assert!(scoped.allows(ip, Some(443)));
    assert!(!scoped.allows(ip, Some(80)));
    // A portless rule permits any port, and only it matches a portless flow.
    let any = build_box_policy(NetworkMode::Allowlist, &["8.8.8.0/24"]);
    assert!(any.allows(ip, Some(80)));
    assert!(any.allows(ip, None));
    assert!(!scoped.allows(ip, None));
    assert!(!any.allows("1.1.1.1".parse().unwrap(), Some(80)));
}

/// Where an entry's host ends decides what it grants, so the ambiguous
/// spellings are pinned here.
#[test]
fn an_entry_is_split_on_the_socketaddr_convention() {
    let split = |e: &str| {
        let (host, port) = split_host_port(e).unwrap();
        (host.to_string(), port)
    };
    assert_eq!(split("[db.local]"), ("db.local".into(), None));
    assert_eq!(split("[db.local]:5432"), ("db.local".into(), Some(5432)));
    assert_eq!(split("db.local:5432"), ("db.local".into(), Some(5432)));
    assert_eq!(split("db.local"), ("db.local".into(), None));
    // A v6 literal is not a host:port pair, whatever `rsplit_once` thinks.
    assert_eq!(split("::1"), ("::1".into(), None));
    assert_eq!(
        split("[2001:db8::1]:443"),
        ("2001:db8::1".into(), Some(443))
    );
    // The prefix length is part of what an entry covers, so it survives:
    // dropping it would turn `0.0.0.0/0` into the single host `0.0.0.0`.
    assert_eq!(split("8.8.8.0/24:443"), ("8.8.8.0/24".into(), Some(443)));
    assert_eq!(split("0.0.0.0/0"), ("0.0.0.0/0".into(), None));

    // An address rule is told apart from a name rule by the host alone.
    for addr in [
        "8.8.8.8",
        "8.8.8.0/24",
        "8.8.8.0/24:443",
        "[::1]:443",
        "::1",
    ] {
        let rule = parse_allow(addr).unwrap();
        assert!(
            matches!(rule, Rule::Addr(..)),
            "{addr} is an address: {rule:?}"
        );
    }
    for name in ["example.com", "api.openai.com:443", "vma.terra"] {
        let rule = parse_allow(name).unwrap();
        assert!(matches!(rule, Rule::Name(..)), "{name} is a name: {rule:?}");
    }
    // …and the one word for the machine terra runs on is neither, in any case.
    for host in [HOST_LOOPBACK_SYMBOL, "host_loopback", "HOST_LOOPBACK:22"] {
        let rule = parse_allow(host).unwrap();
        assert!(
            matches!(rule, Rule::Host(_)),
            "{host} is the host: {rule:?}"
        );
    }

    // An un-bracketed v6 address whose last group also reads as a port is
    // two rules in one spelling, and taking it as the address silently
    // opens every port. Refused, with both spellings named.
    for ambiguous in ["fe80::1:2", "2001:db8::1:443"] {
        let err = parse_allow(ambiguous).unwrap_err().clone();
        assert!(err.contains("un-bracketed"), "{ambiguous}: {err}");
        assert!(err.contains(&format!("[{ambiguous}]")), "{err}");
    }
    // Both of the spellings it names mean exactly one thing.
    assert_eq!(split("[fe80::1:2]"), ("fe80::1:2".into(), None));
    assert_eq!(split("[fe80::1]:2"), ("fe80::1".into(), Some(2)));
    // A v6 literal that could not be read as host:port is left alone -
    // `::1` splits into an empty head, and a hex group is not a port.
    for plain in ["::1", "2001:db8::443", "fe80::abcd"] {
        assert_eq!(split(plain), (plain.into(), None), "{plain}");
    }
    // …and a prefix length keeps a CIDR out of the ambiguity entirely.
    assert_eq!(split("fe80::1:2/64"), ("fe80::1:2/64".into(), None));

    // A present-but-unusable port fails the recipe rather than widening the
    // rule to every port - which is what dropping it would quietly do.
    for bad in [
        "1.1.1.1:",
        "1.1.1.1:0",
        "1.1.1.1:+443",
        "api.test:99999",
        "[::1]:x",
    ] {
        assert!(parse_allow(bad).is_err(), "{bad} should be refused");
    }
    assert!(parse_allow("*.1.2.3.4").is_err());
    // …as do the malformed spellings around brackets and the empty entry.
    for bad in ["", "  ", "[db.local", "[db.local]x"] {
        assert!(parse_allow(bad).is_err(), "{bad:?} should be refused");
    }
    // A name rule that normalizes to nothing is refused, not left inert.
    let err = format_build_error(&build_network(NetworkMode::Allowlist, &["."]));
    assert!(err.contains("not a name"), "{err}");
    // …and a prefix length past the address width is refused, not dropped.
    let err = format_build_error(&build_network(NetworkMode::Allowlist, &["10.0.0.0/33"]));
    assert!(err.contains("prefix length"), "{err}");

    // The bracketed spelling still matches a record, brackets stripped.
    let bracketed = build_published_policy(
        NetworkMode::Allowlist,
        &[build_dns_record("db.local", HOST_LOOPBACK_SYMBOL)],
        &["[db.local]:5432"],
    );
    assert_eq!(bracketed.host_service_ports(), [Some(5432), Some(5432)]);
    assert!(!bracketed.allows(gateway_addresses()[0], Some(5432)));
}

/// A `hosts:` rule is one record: one name, one address. The spellings
/// that would silently collapse into one - or into none - are refused.
#[test]
fn a_hosts_rule_names_exactly_one_answerable_record() {
    let mut network = build_network(NetworkMode::Allowlist, &[]);

    network.hosts = vec![build_dns_record("*.local", HOST_LOOPBACK_SYMBOL)];
    assert!(format_build_error(&network).contains("cannot use '*'"));

    // A name that normalizes to nothing is refused rather than left as a
    // record the gateway silently drops.
    network.hosts = vec![build_dns_record(".", HOST_LOOPBACK_SYMBOL)];
    assert!(format_build_error(&network).contains("can answer"));

    // Duplicates - including a pair differing only in case or by a trailing
    // dot, which the gateway strips. One record would silently own the name.
    for pair in [
        [
            build_dns_record("a.test", HOST_LOOPBACK_SYMBOL),
            build_dns_record("a.test", "10.0.0.5"),
        ],
        [
            build_dns_record("a.test", HOST_LOOPBACK_SYMBOL),
            build_dns_record("A.TEST", "10.0.0.5"),
        ],
        [
            build_dns_record("db.local", HOST_LOOPBACK_SYMBOL),
            build_dns_record("db.local.", "10.0.0.5"),
        ],
    ] {
        network.hosts = pair.to_vec();
        assert!(
            format_build_error(&network).contains("duplicate"),
            "{:?}",
            network.hosts
        );
    }

    // A record's addr is an address, or the one word for the host - any case.
    for bad in ["", "db.other.local", "10.0.0.5:5432", "10.0.0.0/8", "HOST"] {
        network.hosts = vec![build_dns_record("db.local", bad)];
        assert!(
            format_build_error(&network).contains("neither an IP address"),
            "{bad}"
        );
    }
    network.hosts = vec![build_dns_record("db.local", "host_loopback")];
    assert!(
        build_policy(&network).is_ok(),
        "the token is case-insensitive"
    );
    network.hosts = vec![build_dns_record("db.local", "::ffff:1.1.1.1")];
    assert_eq!(
        build_policy(&network).unwrap().static_answer("db.local"),
        Some(["1.1.1.1".parse().unwrap()].as_slice())
    );

    // Distinct names are still distinct.
    network.hosts = vec![
        build_dns_record("a.test", HOST_LOOPBACK_SYMBOL),
        build_dns_record("b.test", HOST_LOOPBACK_SYMBOL),
    ];
    assert!(build_policy(&network).is_ok());
}

#[test]
fn mapped_addresses_cannot_bypass_host_grants() {
    let IpAddr::V4(host) = gateway_addresses()[0] else {
        unreachable!()
    };
    let mapped = IpAddr::V6(host.to_ipv6_mapped());
    for mode in [NetworkMode::Allowlist, NetworkMode::UnrestrictedPublic] {
        let broad = build_box_policy(mode, &["0.0.0.0/0", "::/0"]);
        assert!(!broad.allows(mapped, Some(22)));
        let granted = build_box_policy(mode, &["HOST_LOOPBACK:443"]);
        assert!(!granted.allows(mapped, Some(443)));
        assert_eq!(granted.host_service_ports(), [Some(443)]);
    }
}

#[test]
fn resolved_answers_are_canonical_unique_and_port_scoped() {
    let public: IpAddr = "1.1.1.1".parse().unwrap();
    let mapped: IpAddr = "::ffff:1.1.1.1".parse().unwrap();
    let private: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    for mode in [NetworkMode::Allowlist, NetworkMode::UnrestrictedPublic] {
        let rules = if mode == NetworkMode::Allowlist {
            vec!["API.TEST.:443", "api.test:8443"]
        } else {
            vec![]
        };
        let p = build_box_policy(mode, &rules);
        assert_eq!(
            p.accept_resolved("Api.Test.", &[mapped, public, private, mapped]),
            [public]
        );
        assert!(p.allows(mapped, Some(443)));
        assert!(p.allows(public, Some(8443)));
        assert_eq!(
            p.allows(public, Some(80)),
            mode == NetworkMode::UnrestrictedPublic
        );
        assert_eq!(
            p.learned_dns.lock().unwrap().len(),
            if mode == NetworkMode::Allowlist { 2 } else { 0 }
        );
    }
}

#[test]
fn learned_grants_expire_independently_and_refresh_without_shortening() {
    use std::time::{Duration, Instant};
    let p = build_box_policy(NetworkMode::Allowlist, &["api.test:443", "api.test:8443"]);
    let ip = "1.1.1.1".parse().unwrap();
    p.accept_resolved("api.test", &[ip]);
    let now = Instant::now();
    {
        let mut cache = p.learned_dns.lock().unwrap();
        let expires = *cache.peek(&(ip, Some(443))).unwrap();
        assert!(expires > now && expires <= now + Duration::from_mins(1));
        cache.put((ip, Some(443)), now);
        cache.put((ip, Some(8443)), now + Duration::from_mins(2));
    }
    assert!(!p.allows(ip, Some(443)));
    assert!(p.allows(ip, Some(8443)));
    assert!(!p.allows(ip, None));
    p.accept_resolved("api.test", &[ip]);
    assert!(p.allows(ip, Some(443)));
    assert_eq!(
        *p.learned_dns
            .lock()
            .unwrap()
            .peek(&(ip, Some(8443)))
            .unwrap(),
        now + Duration::from_mins(2)
    );
    p.learned_dns.lock().unwrap().put((ip, None), now);
    assert!(!p.allows(ip, Some(80)));
}

#[test]
fn using_a_record_preserves_it_across_lru_eviction() {
    let p = build_box_policy(NetworkMode::Allowlist, &["api.test"]);
    let first: IpAddr = "1.1.0.0".parse().unwrap();
    let second: IpAddr = "1.1.0.1".parse().unwrap();
    for i in 0..LEARNED_ADDRESSES_CAPACITY {
        let ip = IpAddr::V4(std::net::Ipv4Addr::from(
            0x0101_0000 + u32::try_from(i).unwrap(),
        ));
        p.accept_resolved("api.test", &[ip]);
    }
    assert!(p.allows(first, None));
    p.accept_resolved("api.test", &["2.2.2.2".parse().unwrap()]);
    assert_eq!(
        p.learned_dns.lock().unwrap().len(),
        LEARNED_ADDRESSES_CAPACITY
    );
    assert!(p.allows(first, None));
    assert!(!p.allows(second, None));
}

#[test]
fn poisoned_dns_cache_denies_learning_without_revoking_explicit_grants() {
    let p = build_published_policy(
        NetworkMode::Allowlist,
        &[build_dns_record("static.test", "10.0.0.5")],
        &["api.test:443", "static.test:80", "HOST_LOOPBACK:22"],
    );
    let public = "1.1.1.1".parse().unwrap();
    p.accept_resolved("api.test", &[public]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _cache = p.learned_dns.lock().unwrap();
        panic!("poison the cache");
    }));
    assert!(result.is_err());
    assert_eq!(
        p.accept_resolved("api.test", &[public]),
        [] as [std::net::IpAddr; 0]
    );
    assert!(!p.allows(public, Some(443)));
    assert!(p.allows("10.0.0.5".parse().unwrap(), Some(80)));
    assert_eq!(p.host_service_ports(), [Some(22)]);
    assert!(!p.allows(gateway_addresses()[0], Some(22)));
    assert!(matches!(
        p.lookup_name("STATIC.TEST."),
        NameLookup::Static(_)
    ));
}

#[test]
fn direct_dns_and_host_service_capabilities_match_the_recipe() {
    for mode in [NetworkMode::Allowlist, NetworkMode::UnrestrictedPublic] {
        let empty = build_box_policy(mode, &[]);
        assert_eq!(empty.blocks_direct_dns(), mode == NetworkMode::Allowlist);
        assert_eq!(empty.host_service_ports(), []);
        let static_only = build_published_policy(
            mode,
            &[build_dns_record("host.test", HOST_LOOPBACK_SYMBOL)],
            &[],
        );
        assert!(static_only.blocks_direct_dns());
        assert_eq!(static_only.host_service_ports(), []);
        let p = build_box_policy(mode, &["HOST_LOOPBACK", "HOST_LOOPBACK:443"]);
        assert_eq!(p.host_service_ports(), [None, Some(443)]);
        assert!(!p.allows(gateway_addresses()[1], None));
        assert_eq!(
            p.accept_resolved("ungranted.test", &[]),
            [] as [std::net::IpAddr; 0]
        );
    }
}

#[test]
fn unmatched_or_empty_names_never_gain_allowlist_authority() {
    let p = build_box_policy(NetworkMode::Allowlist, &["api.test:443"]);
    for name in [
        "",
        ".",
        "a..test",
        "a.test\0",
        "a.test/",
        "a.test:443",
        "☃.test",
    ] {
        assert!(p.grants_for(name).is_empty(), "{name:?}");
        assert!(p.static_answer(name).is_none());
        assert!(matches!(p.lookup_name(name), NameLookup::Denied));
        assert_eq!(
            p.accept_resolved(name, &["1.1.1.1".parse().unwrap()]),
            [] as [std::net::IpAddr; 0]
        );
    }
}

#[test]
fn concurrent_learning_preserves_port_scope_and_box_isolation() {
    let p = build_box_policy(NetworkMode::Allowlist, &["api.test:443"]);
    let other = build_box_policy(NetworkMode::Allowlist, &["api.test:443"]);
    std::thread::scope(|scope| {
        for i in 1..=8 {
            let p = &p;
            scope.spawn(move || {
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, i));
                for _ in 0..64 {
                    assert_eq!(p.accept_resolved("api.test", &[ip]), [ip]);
                    assert!(p.allows(ip, Some(443)));
                    assert!(!p.allows(ip, Some(80)));
                }
            });
        }
    });
    assert_eq!(p.learned_dns.lock().unwrap().len(), 8);
    for i in 1..=8 {
        assert!(!other.allows(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, i)), Some(443)));
    }
}
