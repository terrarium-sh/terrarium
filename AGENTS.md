# AGENTS.md

## Verifying Changes

*   **CI Standard:** `make verify` (formatting, Clippy, docs, tests, and the
    script checks). Run it before handing off.
*   **Rust-only Fast Path:**
    ```sh
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings # Pedantic, denies warnings
    cargo test --workspace # Use `cargo test -p terra --lib` for terra units
    ```
*   **Scripts read Rust sources:** checks under `scripts/` parse source text
    (fixture paths in `test_fixtures.rs`). The fast path skips them; after
    moving or renaming code, run `make verify-source`.
*   **Agent skill:** `skills/terra-box/SKILL.md` is rendered from
    `packaging/agent-skill.md` and `docs/{recipe,manifest}.md`. After editing
    any of them, run `make skill` and commit the result; `make verify-source`
    fails on drift.
*   **CLI Updates:** `crates/terra/src/cli.rs` is the source of truth for the man
    pages; `make man` re-renders them (they are generated, not committed).
*   **Boot Tests:** Requires `/dev/kvm`. Run: `make dist && TERRA_BIN=$PWD/dist/terra cargo test -p terra --test boot -- --ignored`
*   **Feature acceptance:** `sh acceptance/run.sh --terra dist/terra` (Windows:
    `acceptance/run.ps1`). Keep both runners' steps identical; a new
    user-facing feature gets a step in both.
*   **Seccomp policy:** the Linux allowlists in
    `crates/terra-sandbox/src/linux/policy/` are generated from code, not
    written by hand. After a change that can alter which syscalls a sandboxed
    role reaches (new code paths, dependency or toolchain bumps), run
    `make policy` on each Linux architecture and commit the reviewed diff;
    CI's `make policy-check` fails on any drift. When the generator refuses a
    site, make the code analyzable rather than widening the policy by hand. New
    host operations still need boot-test coverage, which runs under the
    allowlist.

## Threat model

Terra's filesystem defenses protect the VM boundary: a guest must not use its
guest filesystem or configured mounts to escape into the host or gain host
privileges. The host and its box filesystems are trusted; guest-written share
contents are not treated as a host security boundary, and concurrent host
local mutation is out of scope. Host-side code should therefore stay KISS and
should not add elaborate defenses without a new threat-model requirement.

## Portability

`crates/terra-agent/` and `crates/terra-protocol/` must be built with portability in mind for Linux, macOS, and Windows. Isolate platform-specific APIs behind explicit conditional compilation and keep shared code platform-neutral.

Other crates also carry `cfg(windows)` and `cfg(target_os = "macos")` paths, so
a Linux build does not compile them. Clippy the workspace for
`x86_64-pc-windows-gnu` and `aarch64-apple-darwin` when touching shared APIs;
Wasmtime's build script needs a C compiler, so point `CC_<triple>` at a wrapper
that drops `--target=*`, `-arch`, `arm64`, `-mmacosx-version-min=*`, and `-Wl,-O?`
and runs `zig cc -target x86_64-windows-gnu` / `aarch64-macos`, with
`AR_<triple>` set to `zig ar`.

## Comments

**Default: no comment.** Code and names carry the *what*; a comment exists only
for a *why* the code cannot state. Before keeping one, grep for its rationale in
the tests and in the definition that owns the concept; if a rename can absorb it
or it is already pinned elsewhere, the comment goes.

*   **Delete** if the comment restates the code or the name at first sight (a
    doc that lists the function body's lines, a variant doc that repeats the
    match arm's guard).
*   **Delete** if a test's doc comment already states the rationale, even
    near-verbatim, and that test fails when the code is "simplified". The
    test's copy is the pinned one; with no such test, the code keeps its why.
*   **Point, don't repeat,** when the code looks deliberately wrong (an odd
    ordering, a mismatched fixture): one line, `see <test_name>`. Keep these
    rare — nothing checks that the test name still exists.
*   **Delete** if the rationale lives at the thing's definition (a helper's doc,
    an enum variant's doc, a module doc). Use sites stay silent or point:
    `see [Foo]`.
*   **Delete** if the doc names another command instead of saying what the code
    does ("Answer whether terra setup would…" is wrong; describe the act).
*   **Keep** security rationales (name the attack and the trigger), deliberate
    inaction (why the obvious change is wrong), non-obvious ordering (lock
    before delete), platform quirks, and what a signature cannot say: what
    `Ok(())` or `Ok(None)` means, a bool param that cannot become an enum
    (fixed by WIT or a trait), or a tuple/`(File, bool)` return's flag.
*   **Keep** `SAFETY:` on `unsafe` and `ponytail:` debt markers.
*   **Rename over annotate:** if the comment exists to decode a vague name,
    rename instead. Precedent: adopt → new_pin, Suspect → GuestWritableFile,
    file → recipe_or_manifest, Pinning → PinAction, repinned_by_manifest →
    manifest_divergence, KILL_GRACE → KILL_REAP_WAIT, (File, bool) →
    PreparedBox { lock, fresh_rootfs }, readonly: bool → AccessMode. Names
    must match reality: no past tense for would-be states, no `check_`/`has_`
    prefix on a function that returns the thing.
*   **Invariants are enforced, never narrated:** a comment claiming a property
    ("every field is accounted for", "these stay the same length") needs the
    test or compile-time shape (exhaustive destructure, type, const) that fails
    when it breaks — otherwise reword it as intent or delete it.

**Style, when keeping:**

*   **Budget:** at most two sentences; one clause is usually enough.
*   **Short sentences; name the referent** — no "it" that could be anything.
*   **Hypotheticals:** "would" for what happens *without* the code; present
    tense for what the code does.
*   **Module docs:** one or two lines naming the module's job, no route-maps.
*   **Enum/struct docs:** one line naming what the type is; variant docs go
    unless a name alone cannot carry the meaning.
*   **User-facing error/help text is a legitimate home for the why;** a
    comment repeating it gets deleted (clap help text is the pinned copy).
*   **Examples go in the doc only if the user asks for one**, mirroring the
    scenario the test already plays.
*   **Tests are exempt** from the budget: a test's doc comment states the
    property it pins, at whatever length that takes.

## Naming

**Self-documenting names are the first line of explanation.**

*   **Be Descriptive:** Prefer `uncommitted_dirty_files` over `files`.
*   **Types & Policies:** Name what they are (`SessionOutcome`), not when they happen; types are nouns.
*   **Functions:** Name ordinary functions as verb phrases describing an action
    (`resolve_pinned_box`, `send_file_into_box`). Rust trait methods,
    constructors, and established conversion APIs (`from_*`, `into_*`, `as_*`,
    `to_*`) may follow their idiomatic names.
*   **Variables:** Name values as nouns describing what they hold
    (`uncommitted_dirty_files`); name booleans as truthful predicates using
    `is_`, `has_`, or `can_` when those prefixes fit.
*   **Constants:** Use descriptive `SCREAMING_SNAKE_CASE` names
    (`MAX_GUEST_CLAIMED_BYTES`), and import them under their own name rather
    than re-exporting an alias.
*   **Enums over bare bools:** a parameter whose call sites read `f(x, true)`
    becomes an enum (`AccessMode::ReadOnly`, `Denial::NameLookup`).
*   **Sibling names pair up:** names that answer each other read together
    (`takes_the_box` / `takes_only_the_box`).
*   **The name is the contract at the use site:** if a call site needs the
    comment to decode it, the name is wrong (`EGRESS_FLOOR` over `FLOOR_MODE`,
    `MAX_GUEST_CLAIMED_BYTES` over `MAX_CP_BYTES`).
*   **Related names stay consistent:** use one term for one concept and keep
    shared stems and parts of speech aligned across an API.
*   **Avoid Shadowing:** Do not name a local variable the same as a module it calls (e.g., don't use `state` if calling `state::get()`).
*   **Extract Closures:** Turn complex inline closures into named functions.
*   **CLI Flags:** Name them for what they actually do (`--rebuild`), not past usage (`--force`). Update the README when renaming.

## Structure

*   **Exhaustive matches, no wildcard:** a new variant is a compile error until
    classified, so the decision is made where the type lives — not in a
    hardcoded list that renames can break.
*   **One definition for anything rendered twice** (help texts, config
    output), pinned against clap/serde by tests in both directions.
*   **One owner per protocol fact:** interface names, register offsets, limits,
    and artifact names are one constant in the module that owns the protocol;
    everything else imports it, and messages format the constant instead of
    restating its value. Tests that pin an external contract keep the literal.
*   **Component streams go through `component::relay`:** host code hands the
    guest an async stream, channel, or `TryWrite` buffer and stays plain async;
    `StreamProducer`/`StreamConsumer` impls live only in `relay`. A writer doing
    its own I/O drains a `byte_channel` on a tokio task; a writer into host
    memory uses `DirectSink`.
*   **Derive facts from types and tests; hardcode only decisions.** A UI
    decision ("does `terra <verb> dev` get a hint") is written down, not
    computed at runtime.

## User-facing text

*   **Short; lead with what it is**, not what it isn't.
*   **Examples go in `after_long_help`** — `-h` stays a summary.
*   **Errors name the mistake and the fix**, or offer the working spelling.
*   **Machine-readable outputs prefer `snake_case`** (JSON
    keys, serialized enum variants like `setting_up`, `not_created`).
