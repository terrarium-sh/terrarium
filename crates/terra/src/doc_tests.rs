//! Security docs quote these bounds; each phrase is rendered from the constant that enforces it.

fn read_doc(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// A changed constant or a hand-edited doc number fails here until both agree again.
#[test]
fn security_docs_quote_the_enforced_bounds() {
    use terra_runtime::box_runtime::{DEFAULT_COMPONENT_MEMORY_MIB, NETWORK_FRONTEND_MEMORY_BYTES};
    let quotes = [
        (
            "security.md",
            format!(
                "Learned DNS grants expire for new connections after {} seconds",
                terra_policy::LEARNED_DNS_TTL_SECS
            ),
        ),
        (
            "security.md",
            format!(
                "an {} MiB per-file cap",
                terra_limits::MAX_LOG_FILE_BYTES >> 20
            ),
        ),
        (
            "security.md",
            format!(
                "{DEFAULT_COMPONENT_MEMORY_MIB} MiB by default, {} MiB for the network device so its {}-flow table fits. A configured limit must be at least {DEFAULT_COMPONENT_MEMORY_MIB} MiB",
                NETWORK_FRONTEND_MEMORY_BYTES >> 20,
                terra_protocol::vsock::MAX_NETWORK_SOCKETS,
            ),
        ),
        (
            "component-authority.md",
            format!(
                "limits each range to {} KiB, each call to {} ranges and {} KiB total",
                terra_limits::MAX_SINGLE_GUEST_COPY_BYTES >> 10,
                terra_limits::MAX_BATCH_GUEST_COPY_RANGES,
                terra_limits::MAX_BATCH_GUEST_COPY_BYTES >> 10,
            ),
        ),
    ];
    for (doc, quote) in quotes {
        assert!(
            read_doc(doc).contains(&quote),
            "docs/{doc} must say: {quote}"
        );
    }
}
