use super::*;

/// The two directories a load spends: the shell's, which finds the recipe
/// file, and the box's, which its mounts are relative to.
fn load_from(arg: &str, cwd: &Path, project_dir: &Path) -> Result<Config> {
    let recipe = crate::resolve::read_recipe(arg, cwd)?
        .ok_or_else(|| crate::resolve::no_such_recipe(arg, arg, cwd))
        .context("resolving the recipe")?;
    parse_recipe(&recipe.text, project_dir, &recipe.from)
}

fn load(arg: &str, cwd: &Path) -> Result<Config> {
    load_from(arg, cwd, cwd)
}

/// [`parse_recipe`] and the [`merge_env_file`] step that follows it in
/// [`crate::resolve::ResolvedBox::parsed_recipe`] - together, a full read of a
/// recipe.
fn read_fully(text: &str, project_dir: &Path, source: &Path) -> Result<Config> {
    let mut cfg = parse_recipe(text, project_dir, source)?;
    merge_env_file(&mut cfg)?;
    Ok(cfg)
}

/// A relative `host:` belongs to the box, so it resolves against the
/// directory the box is of - not the one the shell happens to be in, which
/// would give `terra --project` a different filesystem per caller.
#[test]
fn a_relative_mount_resolves_against_the_project_directory() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::create_dir_all(elsewhere.join("src")).unwrap();
    std::fs::write(
        elsewhere.join("cfg.yaml"),
        "mounts:\n  - host: src\n    guest: /work\n",
    )
    .unwrap();

    // The recipe path is the shell's to resolve; the mount inside it is the
    // box's: standing in `elsewhere`, `./cfg.yaml` is found there - and its
    // `src` is still the *project's*.
    let cfg = load_from("./cfg.yaml", &elsewhere, &project).unwrap();
    assert_eq!(cfg.mounts[0].host, project.join("src"));
}

/// Reading a recipe must not depend on its shares being there: a guest with
/// a writable share can delete a directory a *sibling* mount names, and the
/// pinned recipe is what the adoption gate reads to decide whether a guest
/// could have authored the next one. Existence is a boot's question.
#[test]
fn parsing_a_recipe_does_not_touch_the_host_paths_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();
    let yaml = "mounts:\n  - host: ./gone\n    guest: /work\n";

    let mut cfg = parse_recipe(yaml, project, Path::new("r.yaml")).unwrap();
    assert_eq!(
        cfg.mounts[0].host,
        project.join("gone"),
        "a relative host is still made absolute against the project"
    );

    let err = resolve_mounts(&mut cfg).unwrap_err().to_string();
    assert!(err.contains("does not exist"), "{err}");

    std::fs::create_dir(project.join("gone")).unwrap();
    resolve_mounts(&mut cfg).unwrap();
    assert_eq!(
        cfg.mounts[0].host,
        std::fs::canonicalize(project.join("gone")).unwrap()
    );
}

#[test]
fn relative_mount_resolved_against_cwd() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().to_path_buf();
    std::fs::create_dir(cwd.join("src")).unwrap();

    let yaml = "hw:\n  cpus: 1\n  mem_mib: 512\nmounts:\n  - host: src\n    guest: /work\nnetwork:\n  mode: allowlist\n  allow:\n    - example.com:443\nhooks:\n  on_start:\n    - echo hi\n";
    std::fs::write(cwd.join("cfg.yaml"), yaml).unwrap();
    let cfg = load("./cfg.yaml", &cwd).unwrap();
    assert_eq!(cfg.mounts[0].host, cwd.join("src"));
    assert_eq!(cfg.hw.cpus, 1);
    assert_eq!(cfg.hw.mem_mib, 512);
    assert_eq!(cfg.hw.rootfs_mib, 512); // untouched fields still get their default
    assert_eq!(cfg.network.mode, NetworkMode::Allowlist);
    assert_eq!(cfg.network.allow, vec!["example.com:443".to_string()]);
    assert_eq!(cfg.hooks.on_start, vec!["echo hi"]);
}

/// A recipe's daemons are shell lines, taken as written.
#[test]
fn daemons_parse_and_default_empty() {
    let cfg: Config = yaml_serde::from_str("daemons: [ascend]\n").unwrap();
    assert_eq!(cfg.daemons, vec!["ascend"]);
    let none: Config = yaml_serde::from_str("{}").unwrap();
    assert!(none.daemons.is_empty());
}

/// The recipe's own spellings, refused variants included.
#[test]
fn network_mode_parses_from_yaml_scalar() {
    assert_eq!(
        yaml_serde::from_str::<NetworkMode>("allowlist").unwrap(),
        NetworkMode::Allowlist
    );
    assert_eq!(
        yaml_serde::from_str::<NetworkMode>("unrestricted-public").unwrap(),
        NetworkMode::UnrestrictedPublic
    );
    // The short spelling is refused with an error naming the replacement,
    // not aliased.
    let err = yaml_serde::from_str::<NetworkMode>("unrestricted")
        .unwrap_err()
        .to_string();
    assert!(err.contains("unrestricted-public"), "{err}");
    // What terra writes back keeps that spelling.
    assert_eq!(
        yaml_serde::to_string(&NetworkMode::UnrestrictedPublic)
            .unwrap()
            .trim(),
        "unrestricted-public"
    );
    assert!(yaml_serde::from_str::<NetworkMode>("isolated").is_err());
}

#[test]
fn env_map_parses() {
    let cfg: Config = yaml_serde::from_str("env:\n  MODEL: gpt-4o\n  DEBUG: \"1\"\n").unwrap();
    assert_eq!(cfg.env.get("MODEL").map(String::as_str), Some("gpt-4o"));
    assert_eq!(cfg.env.get("DEBUG").map(String::as_str), Some("1"));
    let none: Config = yaml_serde::from_str("hw:\n  cpus: 1\n  mem_mib: 64\n").unwrap();
    assert!(none.env.is_empty());
}

/// `env_file:` merges over `env:` - the file wins - and a relative path
/// is the box project's, like every other path in a recipe.
#[test]
fn env_file_merges_over_env() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("secrets.env"),
        "# comment\n\nA=from-file\nB=only-file\n",
    )
    .unwrap();
    let cfg = read_fully(
        "env:\n  A: from-recipe\n  C: only-recipe\nenv_file: secrets.env\n",
        dir.path(),
        Path::new("r.yaml"),
    )
    .unwrap();
    assert_eq!(cfg.env["A"], "from-file"); // the file wins
    assert_eq!(cfg.env["B"], "only-file"); // only in the file
    assert_eq!(cfg.env["C"], "only-recipe"); // only in the recipe
}

#[test]
fn a_bad_env_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bad.env"), "NO_EQUALS\n").unwrap();
    let err = read_fully("env_file: bad.env\n", dir.path(), Path::new("r.yaml"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("KEY=VAL"), "{err}");

    let err = read_fully("env_file: missing.env\n", dir.path(), Path::new("r.yaml"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("opening env file"), "{err}");

    // A space around the `=` is refused rather than trimmed off the name
    // alone: `A = 1` used to export `A` with a value of " 1", which nothing
    // comparing that string in the guest can match and no message explains.
    std::fs::write(dir.path().join("spaced.env"), "A = 1\n").unwrap();
    let err = read_fully("env_file: spaced.env\n", dir.path(), Path::new("r.yaml"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("environment variable"), "{err}");
    assert!(err.contains("KEY=VAL"), "the spelling that works: {err}");
}

/// An `env_file:` that is not there must not stop the recipe *parsing*: a
/// guest with a writable share can delete the dotenv a box's pinned recipe
/// names, and the authorship gate re-parses every sibling's pin to find the
/// shares one of them could have written a new recipe through. A parse that
/// failed here took those shares out of the question, and the pin went
/// through unwarned. Reading the file is a later step for exactly this.
#[test]
fn a_deleted_env_file_does_not_stop_the_recipe_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let recipe = "mounts:\n  - {host: ., guest: /work}\nenv_file: ./gone.env\n";

    let mut cfg = parse_recipe(recipe, dir.path(), Path::new("r.yaml"))
        .expect("a missing env_file is not a parse failure");
    assert_eq!(cfg.mounts[0].host, dir.path(), "the shares are still there");
    assert_eq!(
        cfg.env_file.as_deref(),
        Some(dir.path().join("gone.env").as_path()),
        "the path is settled at parse time; only the read is deferred"
    );

    // …and the read itself still fails, for whoever actually wanted it.
    let err = merge_env_file(&mut cfg).unwrap_err().to_string();
    assert!(err.contains("opening env file"), "{err}");
}

/// `export KEY=val` is how every dotenv written to be `source`d spells a
/// line, and it parses here as a *name with a space in it*: PID 1 exports
/// that, and nothing in the guest can read `KEY`. It has to fail the
/// recipe, since the alternative is a variable that silently never
/// arrives, and it is refused rather than stripped, because a name nobody
/// typed is not terra's to invent.
#[test]
fn a_shell_export_prefix_in_an_env_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shell.env"), "export API_KEY=sk-1\n").unwrap();
    let err = read_fully("env_file: shell.env\n", dir.path(), Path::new("r.yaml"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("export"), "the fix is named: {err}");
    assert!(err.contains("KEY=VAL"), "{err}");

    // The plain spelling of that same line is what works - and the value is
    // taken literally, quotes and all, which is why they are not written.
    std::fs::write(dir.path().join("plain.env"), "API_KEY=sk-1\nQ=\"quoted\"\n").unwrap();
    let cfg = read_fully("env_file: plain.env\n", dir.path(), Path::new("r.yaml")).unwrap();
    assert_eq!(cfg.env["API_KEY"], "sk-1");
    assert_eq!(cfg.env["Q"], "\"quoted\"");
}

/// `~alice` is the *shell's* expansion, and terra never sees it expanded
/// when it is quoted or comes out of a recipe. Left alone it silently
/// became a relative path - `<project>/~alice/data` - and surfaced a step
/// later as a mount host that does not exist, which names neither the
/// mistake nor the fix. Refused in the one function every recipe path goes
/// through, so mounts, `env_file:` and recipe references all say it.
#[test]
fn another_users_home_is_refused_not_silently_made_relative() {
    let err = expand_tilde(Path::new("~alice/data"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("absolute path"), "the fix is named: {err}");

    // The current user's `~` still expands, and nothing else changes: a
    // `~` anywhere but the first component is an ordinary name.
    assert_eq!(
        expand_tilde(Path::new("~/x")).unwrap(),
        std::env::home_dir().unwrap().join("x")
    );
    assert_eq!(
        expand_tilde(Path::new("src/x")).unwrap(),
        PathBuf::from("src/x")
    );
    assert_eq!(
        expand_tilde(Path::new("src/~odd")).unwrap(),
        PathBuf::from("src/~odd")
    );

    // …and it reaches the recipe, which is where anyone would meet it.
    let err = parse_recipe(
        "mounts:\n  - {host: \"~alice/data\", guest: /work}\n",
        Path::new("/proj"),
        Path::new("r.yaml"),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("absolute path"), "{err}");
}

/// A name the guest cannot export must fail the recipe: `setenv` in PID 1
/// panics on it, which is a reboot loop rather than a message.
#[test]
fn env_the_guest_cannot_export_is_refused() {
    for yaml in [
        "env:\n  \"\": oops\n",
        "env:\n  \"FOO=BAR\": x\n",
        "env:\n  FOO: \"a\\0b\"\n",
        "env:\n  \"FO\\0O\": x\n",
        // Whitespace: an exported name nothing in the guest can read.
        "env:\n  \"export FOO\": x\n",
        "env:\n  \"FOO BAR\": x\n",
        "env:\n  \"FOO\\tBAR\": x\n",
    ] {
        let err = parse_recipe(yaml, Path::new("/proj"), Path::new("r.yaml"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("environment variable"),
            "{yaml:?} should be refused: {err}"
        );
    }
    // A value may contain `=`; only names are restricted.
    let ok = parse_recipe(
        "env:\n  API_KEY: sk-with=equals\n",
        Path::new("/proj"),
        Path::new("r.yaml"),
    )
    .unwrap();
    assert_eq!(ok.env["API_KEY"], "sk-with=equals");
}

/// A manifest is references only, and a reference is a path: a bare word
/// would read as a box name, one argument meaning two things. Refused with
/// the spelling that works - and only a manifest that is not there at all
/// reads as "none", so an unreadable one cannot silently change what a
/// bare name means.
#[test]
fn a_manifest_reference_must_be_a_recipe_path() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(MANIFEST_FILE), "boxes:\n  dev: pi-dev\n").unwrap();
    let err = load_manifest(dir.path()).unwrap_err().to_string();
    assert!(err.contains("not a recipe path"), "{err}");
    assert!(
        err.contains("./pi-dev.yaml"),
        "the fix is spelled out: {err}"
    );

    std::fs::write(
        dir.path().join(MANIFEST_FILE),
        "boxes:\n  dev: ./dev.yaml\n",
    )
    .unwrap();
    assert!(load_manifest(dir.path()).unwrap().is_some());

    assert!(
        load_manifest(&dir.path().join("not-there"))
            .unwrap()
            .is_none(),
        "a missing manifest is no manifest"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.path().join(MANIFEST_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_to_string(&path).is_err() {
            // Skipped as root, which reads through 0o000.
            let err = format!("{:#}", load_manifest(dir.path()).unwrap_err());
            assert!(err.contains("reading"), "{err}");
        }
    }
}

/// Container-level `#[serde(default)]` must not leak into structs without it.
#[test]
fn unknown_keys_and_missing_required_fields_are_refused() {
    assert!(yaml_serde::from_str::<Config>("hw:\n  cpus: 1\n  nope: 2\n").is_err());
    assert!(yaml_serde::from_str::<Config>("nope: 1\n").is_err());
    assert!(yaml_serde::from_str::<Mount>("guest: /work\n").is_err());
    assert!(yaml_serde::from_str::<StaticDnsRecord>("name: db\n").is_err());
}

#[test]
fn volume_names_are_validated() {
    let try_parse = |yaml: &str| parse_recipe(yaml, Path::new("/proj"), Path::new("/proj/r.yaml"));
    assert!(try_parse("volumes:\n  - {name: data, guest: /data, size_mib: 64}\n").is_ok());
    // The name is required - it keys the image file.
    assert!(try_parse("volumes:\n  - {guest: /data, size_mib: 64}\n").is_err());
    // Duplicates would mount one image read-write twice.
    assert!(
        try_parse(
            "volumes:\n  - {name: d, guest: /a, size_mib: 64}\n  - {name: d, guest: /b, size_mib: 64}\n"
        )
        .is_err()
    );
    // The name becomes a filename - no separators or traversal.
    assert!(try_parse("volumes:\n  - {name: ../x, guest: /a, size_mib: 64}\n").is_err());

    // Past the last device letter it used to panic rather than error.
    let many = |n: usize| {
        use std::fmt::Write as _;
        let mut y = String::from("volumes:\n");
        for i in 0..n {
            let _ = writeln!(y, "  - {{name: v{i}, guest: /v{i}, size_mib: 1}}");
        }
        try_parse(&y)
    };
    assert!(many(terra_shared::MAX_VOLUMES).is_ok());
    let err = many(terra_shared::MAX_VOLUMES + 1).unwrap_err().to_string();
    assert!(err.contains("at most"), "{err}");
}

/// doas fails closed on a parse error: a smuggled entry revokes every
/// grant rather than widening any.
#[test]
fn sudo_entries_are_normalized_to_bare_commands() {
    let try_parse = |yaml: &str| parse_recipe(yaml, Path::new("/proj"), Path::new("/proj/r.yaml"));
    assert_eq!(try_parse("sudo:\n  - apk\n").unwrap().sudo, vec!["apk"]);

    // Trimmed so whitespace cannot ride into the rule - `"\napk"` is one
    // token, which passed the old check.
    for yaml in ["sudo:\n  - \"  apk  \"\n", "sudo:\n  - \"\\napk\"\n"] {
        assert_eq!(try_parse(yaml).unwrap().sudo, vec!["apk"], "{yaml:?}");
    }

    for bad in [
        "sudo:\n  - apk add git\n",    // arguments never match
        "sudo:\n  - \"   \"\n",        // empty once trimmed
        "sudo:\n  - \"a\\u0007pk\"\n", // an interior control byte
        "sudo:\n  - \"apk\\ndoas\"\n", // two rules smuggled into one entry
    ] {
        let err = try_parse(bad).unwrap_err().to_string();
        assert!(
            err.contains("bare command") || err.contains("not empty strings"),
            "{bad:?} should be refused by the guard, not by chance: {err}"
        );
    }
}

/// A `network:` section the gateway cannot be built from must fail the
/// recipe too: the gateway is started in the background VM process, so a
/// rule refused there is refused *after* `terra setup` pinned the recipe
/// and listed that very rule on the page the approving `y` was given to.
#[test]
fn a_network_section_the_gateway_is_refused_by_fails_the_recipe() {
    let try_parse = |yaml: &str| parse_recipe(yaml, Path::new("/proj"), Path::new("/proj/r.yaml"));
    for (yaml, wanted) in [
        ("network:\n  allow: [\"10.0.0.0/33\"]\n", "prefix length"),
        (
            "network:\n  allow: [\"*.*.example.com\"]\n",
            "only wildcard",
        ),
        ("network:\n  allow: [\"1.1.1.1:0\"]\n", "not a port"),
        (
            "network:\n  hosts:\n    - {name: db.local, addr: nope}\n",
            "neither an IP address",
        ),
        (
            "network:\n  hosts:\n    - {name: a.test, addr: 10.0.0.5}\n    \
             - {name: A.TEST, addr: 10.0.0.6}\n",
            "duplicate",
        ),
        (
            "network:\n  mode: unrestricted-public\n  allow: [\"nas.local:445\"]\n",
            "opens nothing",
        ),
    ] {
        let err = try_parse(yaml).unwrap_err().to_string();
        assert!(err.contains(wanted), "{yaml:?}: {err}");
    }
    // …and a section that builds still parses, in either mode.
    assert!(
        try_parse(
            "network:\n  allow: [\"api.test:443\", \"HOST_LOOPBACK:5432\"]\n  \
             hosts:\n    - {name: db.local, addr: HOST_LOOPBACK}\n"
        )
        .is_ok()
    );
}

/// Hardware a hypervisor cannot build must fail the recipe, not the boot: a
/// detached VM's only report is a replayed log, and a guest starved of
/// memory dies part-way through its kernel, which reads as a hang.
#[test]
fn hardware_a_vm_cannot_be_built_from_is_refused() {
    let try_parse = |yaml: &str| parse_recipe(yaml, Path::new("/proj"), Path::new("/proj/r.yaml"));
    let err = try_parse("hw:\n  cpus: 0\n").unwrap_err().to_string();
    assert!(err.contains("hw.cpus"), "{err}");

    let err = try_parse("hw:\n  mem_mib: 16\n").unwrap_err().to_string();
    assert!(err.contains("hw.mem_mib"), "{err}");
    assert!(err.contains("128"), "the floor is named: {err}");

    // The floor itself boots, and so do the defaults.
    assert!(try_parse("hw:\n  cpus: 1\n  mem_mib: 128\n").is_ok());
    assert!(try_parse("{}").is_ok());
}

/// Two entries on one guest path are mounted in recipe order, so the later
/// silently wins and the earlier is a line that does nothing - including
/// across the kinds, where a volume lands on top of a share.
#[test]
fn one_guest_path_carries_one_thing() {
    let try_parse = |yaml: &str| parse_recipe(yaml, Path::new("/proj"), Path::new("/proj/r.yaml"));
    for clash in [
        "mounts:\n  - {host: ./a, guest: /work}\n  - {host: ./b, guest: /work}\n",
        "volumes:\n  - {name: a, guest: /data, size_mib: 8}\n  - {name: b, guest: /data, size_mib: 8}\n",
        "mounts:\n  - {host: ./a, guest: /data}\nvolumes:\n  - {name: v, guest: /data, size_mib: 8}\n",
        // A trailing slash is the same path, and used to slip past.
        "mounts:\n  - {host: ./a, guest: /work}\n  - {host: ./b, guest: /work/}\n",
    ] {
        let err = try_parse(clash).unwrap_err().to_string();
        assert!(err.contains("claimed twice"), "{clash}: {err}");
    }

    // Distinct paths are untouched, nesting included: a volume inside a
    // share is a real arrangement, not a collision.
    assert!(
        try_parse(
            "mounts:\n  - {host: ./a, guest: /work}\nvolumes:\n  - {name: v, guest: /work/target, size_mib: 8}\n"
        )
        .is_ok()
    );
}

#[test]
fn relative_guest_mount_path_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    std::fs::write(
        cwd.join("cfg.yaml"),
        "mounts:\n  - host: .\n    guest: work\n",
    )
    .unwrap();
    let err = load("./cfg.yaml", cwd).unwrap_err().to_string();
    assert!(err.contains("must be absolute"), "{err}");
}

#[test]
fn missing_config_names_the_path() {
    let err = load("no-such-profile-xyz", Path::new("/proj"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("resolving the recipe"), "{err}");
}

/// A guest path: a relative one has no host cwd to mean and would silently
/// land wherever the workload happened to start.
#[test]
fn a_relative_workdir_is_refused() {
    let cwd = std::env::temp_dir();
    let err = parse_recipe(
        "workload:\n  entrypoint: /bin/sh\n  workdir: work\n",
        &cwd,
        Path::new("t.yaml"),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("workdir must be absolute"), "{err}");

    let ok = parse_recipe(
        "workload:\n  entrypoint: /bin/sh\n  workdir: /work\n",
        &cwd,
        Path::new("t.yaml"),
    )
    .unwrap();
    assert_eq!(ok.workload.workdir.unwrap(), Path::new("/work"));
}
