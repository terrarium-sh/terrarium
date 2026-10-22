//! Docs and the agent skill template checked against the code they describe.

use std::collections::BTreeSet;

fn read_repo_text(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
        // A Windows checkout with core.autocrlf has CRLF docs.
        .replace("\r\n", "\n")
}

fn read_doc(name: &str) -> String {
    read_repo_text(&format!("docs/{name}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn list_yaml_blocks(markdown: &str) -> Vec<&str> {
    markdown
        .split("```yaml\n")
        .skip(1)
        .map(|rest| rest.split("```").next().unwrap())
        .collect()
}

fn collect_key_paths(value: &yaml_serde::Value, path: &str, paths: &mut BTreeSet<String>) {
    match value {
        yaml_serde::Value::Mapping(mapping) => {
            for (key, child) in mapping {
                let path = format!("{path}.{}", key.as_str().unwrap());
                collect_key_paths(child, &path, paths);
                paths.insert(path);
            }
        }
        yaml_serde::Value::Sequence(items) => {
            for item in items {
                collect_key_paths(item, &format!("{path}[]"), paths);
            }
        }
        _ => {}
    }
}

fn list_key_paths(value: &yaml_serde::Value) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    collect_key_paths(value, "", &mut paths);
    paths
}

/// The recipe reference introduces its first example with "Every field". A
/// `Config` field missing from it, or a key `Config` no longer has, fails here.
#[test]
fn the_recipe_reference_example_names_every_field() {
    let reference = read_repo_text("docs/recipe.md");
    let example = list_yaml_blocks(&reference)[0];
    let config: crate::config::Config = yaml_serde::from_str(example).unwrap();
    let documented = list_key_paths(&yaml_serde::from_str(example).unwrap());
    let fields = list_key_paths(&yaml_serde::to_value(&config).unwrap());
    let mismatched: Vec<_> = documented.symmetric_difference(&fields).collect();
    assert!(
        mismatched.is_empty(),
        "docs/recipe.md's first example and Config disagree on {mismatched:?}"
    );
}

/// Every YAML block in the agent skill is a manifest or a recipe terra accepts,
/// so the skill cannot teach a field name or value terra refuses.
#[test]
fn agent_skill_examples_are_accepted() {
    let skill = read_repo_text("skills/terra-box/SKILL.md");
    let blocks = list_yaml_blocks(&skill);
    assert_ne!(blocks.len(), 0, "the agent skill has no ```yaml blocks");
    for block in blocks {
        let project = tempfile::tempdir().unwrap();
        if block.starts_with("boxes:") {
            std::fs::write(project.path().join(crate::config::MANIFEST_FILE), block).unwrap();
            crate::config::load_manifest(project.path())
                .unwrap()
                .unwrap();
        } else {
            crate::config::parse_recipe(block, project.path(), &project.path().join("box.yaml"))
                .unwrap_or_else(|error| panic!("{error:#}\n{block}"));
        }
    }
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

/// The dev guide's network bounds tell a host operator how much memory a guest can make terra
/// queue; a changed constant fails here until README.dev.md says the same.
#[test]
fn dev_guide_quotes_the_enforced_network_bounds() {
    use terra_protocol::vsock::{
        FLOW_REPLY_BYTES, FLOW_UPSTREAM_BYTES, MAX_FLOW_REPLY_BYTES, MAX_FLOW_UPSTREAM_BYTES,
        MAX_NETWORK_SOCKETS,
    };
    let guide = read_repo_text("README.dev.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let quotes = [
        format!(
            "inbound datagrams only from the {} most recent peers the socket sent to within {} seconds",
            terra_network::MAX_UDP_OUTBOUND_PEERS,
            terra_protocol::network::UDP_PEER_TTL_SECS,
        ),
        format!(
            "ordered batches of up to {} datagrams per IPC frame",
            terra_protocol::network::MAX_NETWORK_DATAGRAMS
        ),
        format!(
            "| Each TCP/UDP/publication stream | {} KiB | {} KiB |",
            FLOW_UPSTREAM_BYTES >> 10,
            FLOW_REPLY_BYTES >> 10
        ),
        format!(
            "The {MAX_NETWORK_SOCKETS} flows' allowances total {} MiB inside the frontend's {}-MiB Wasm memory floor",
            (MAX_FLOW_UPSTREAM_BYTES + MAX_FLOW_REPLY_BYTES) >> 20,
            terra_runtime::box_runtime::NETWORK_FRONTEND_MEMORY_BYTES >> 20,
        ),
        format!(
            "grants each stream a {} KiB receive window, so {MAX_NETWORK_SOCKETS} flows can queue about {} MiB in each direction",
            terra_network::YAMUX_STREAM_WINDOW_BYTES >> 10,
            (terra_network::YAMUX_STREAM_WINDOW_BYTES * MAX_NETWORK_SOCKETS) >> 20,
        ),
        format!(
            "The broker admits {} resources and {} DNS lookups at once",
            terra_network::MAX_RESOURCES,
            terra_network::MAX_DNS_REQUESTS
        ),
    ];
    for quote in quotes {
        assert!(guide.contains(&quote), "README.dev.md must say: {quote}");
    }
}
