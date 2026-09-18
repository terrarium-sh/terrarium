# AGENTS.md

## Verifying Changes

*   **CI Standard:** `make verify` (runs formatting, Clippy, and tests).
*   **Rust-only Fast Path:**
    ```sh
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings # Pedantic, denies warnings
    cargo test --workspace # Use `cargo test -p terra --lib` for terra units
    ```
*   **CLI Updates:** `crates/terra/src/cli.rs` is the source of truth for the man
    pages and completions; `make man` re-renders them (they are generated, not
    committed).
*   **Boot Tests:** Requires `/dev/kvm`. Run: `make dist && TERRA_BIN=$PWD/dist/terra cargo test -p terra --test boot -- --ignored`

## Threat model

Terra's filesystem defenses protect the VM boundary: a guest must not use its
guest filesystem or configured mounts to escape into the host or gain host
privileges. The host and its box filesystems are trusted; guest-written share
contents are not treated as a host security boundary, and concurrent host
local mutation is out of scope. Host-side code should therefore stay KISS and
should not add elaborate defenses without a new threat-model requirement.

## Portability

`crates/terra-agent/` and `crates/terra-protocol/` must be built with portability in mind for Linux, macOS, and Windows. Isolate platform-specific APIs behind explicit conditional compilation and keep shared code platform-neutral.

## Comments

**Default: no comment.** Code and names carry the *what*; a comment exists only
for a *why* the code cannot state. When in doubt, delete. For every comment,
read the code it sits on, the call sites, and the tests, then decide between:

*   **Delete** if the comment restates what the code or the name says at first
    sight (a doc that lists the function body's lines, a variant doc that
    repeats the match arm's guard).
*   **Delete** if the rationale appears in a test's doc comment. The test's
    copy is the pinned one; grep the tests before keeping any "why". This
    includes near-verbatim overlap, not just exact copies.
*   **Delete** if the rationale lives at the thing's definition elsewhere (a
    helper's doc, an enum variant's doc, a module doc). Use sites stay silent
    or point: `see [Foo]`.
*   **Delete** if the doc names another command instead of saying what the
    code does ("Answer whether terra setup would…" is wrong; describe the act).
*   **Keep** security rationales (name the attack and the trigger), deliberate
    inaction (why the obvious change is wrong), non-obvious ordering (lock
    before delete), platform quirks, and the one thing a signature cannot say:
    what `Ok(())` or `Ok(None)` means, a bare bool param's meaning, a
    tuple/`(File, bool)` return's flag.
*   **Keep** `SAFETY:` on `unsafe` and `ponytail:` debt markers.
*   **Rename over annotate:** if the comment exists to decode a vague name,
    rename instead and delete the comment. Precedent: adopt → new_pin, Suspect
    → GuestWritableFile, file → recipe_or_manifest, Pinning → PinAction,
    repinned_by_manifest → manifest_divergence, KILL_GRACE → KILL_REAP_WAIT,
    (File, bool) → PreparedBox { lock, fresh_rootfs }. Names must match
    reality: no past tense for would-be states, no `check_`/`has_` prefix on a
    function that returns the thing.
*   **Invariants are enforced, never narrated:** a comment claiming a property
    ("every field is accounted for", "these stay the same length") must be
    accompanied by the test or compile-time shape (exhaustive destructure,
    type, const) that fails when the property breaks — or reworded as intent.
    Prose stating an unenforced invariant is a bug, not documentation.

**Style, when keeping:**

*   **Budget:** at most two sentences; one clause is usually enough.
*   **Short sentences; name the referent** — no "it" that could be anything.
*   **Hypotheticals:** "would" for what happens *without* the code; present
    tense for what the code does.
*   **Module docs:** one or two lines naming the module's job. No route-maps
    (each fn's doc owns its part).
*   **Enum/struct docs:** one line naming what the type is; variant docs go
    unless a name alone cannot carry the meaning.
*   **User-facing error/help text is a legitimate home for the why** — a
    comment repeating it gets deleted; clap help text is the rendered, pinned
    copy.
*   **Examples go in the doc only if the user asks for one**, mirroring the
    scenario the test already plays.
*   **Tests are exempt** from the budget: a test's doc comment states the
    property it pins, at whatever length that takes.

**The one habit that catches everything:** before touching a comment, grep for
its rationale in the test module and in the definition that owns the concept.
If it's there, the code copy dies. If a rationale is nowhere, ask: can a
rename absorb it, or is it one of the keep-categories?

**Verify per file:** `cargo clippy --workspace --all-targets -- -D warnings`
and `cargo test -p terra --lib <module>`. Never leave a comment claiming an
invariant nothing enforces — reword as intent or delete.

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
    (`MAX_GUEST_CLAIMED_BYTES`).
*   **Sibling names pair up:** names that answer each other read together
    (`takes_the_box` / `takes_only_the_box`).
*   **The name is the contract at the use site:** if a call site needs the
    comment to decode it, the name is wrong (`EGRESS_FLOOR` over `FLOOR_MODE`,
    `MAX_GUEST_CLAIMED_BYTES` over `MAX_CP_BYTES`).
*   **Related names stay consistent:** use one term for one concept and keep
    shared stems and parts of speech aligned across an API.
*   **Avoid Shadowing:** Do not name a local variable the same as a module it calls (e.g., don't use `state` if calling `state::get()`).
*   **Extract Closures:** Turn complex inline closures into named functions.
*   **CLI Flags:** Name them for what they actually do (`--rebuild`), not past usage (`--force`). Update the README and completions when renaming.

## Structure

*   **Exhaustive matches, no wildcard:** a new variant is a compile error until
    classified, so the decision is made where the type lives — not in a
    hardcoded list that renames can break.
*   **One definition for anything rendered twice** (help texts, config
    output), pinned against clap/serde by tests in both directions.
*   **Derive facts from types and tests; hardcode only decisions.** A UI
    decision ("does `terra <verb> dev` get a hint") is written down, not
    computed at runtime.

## User-facing text

*   **Short; lead with what it is**, not what it isn't.
*   **Examples go in `after_long_help`** — `-h` stays a summary.
*   **Errors name the mistake and the fix**, or offer the working spelling.
*   **Machine-readable outputs prefer `snake_case`** (JSON
    keys, serialized enum variants like `setting_up`, `not_created`).
