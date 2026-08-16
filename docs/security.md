# Security model

**The boundary is the VM.** A hostile workload is contained by libkrun/KVM and
nothing else in this design is asked to hold it. Everything below is either a
deliberate hole through that boundary, or ergonomics inside it.

What crosses the boundary, because you asked it to:

- **`mounts`** — the listed host directories, read-write unless `readonly`.
  Writes land as *your* host user (the guest's uid 1000 is mapped to it), so a
  guest can do anything to those paths that you could — including creating real
  host symlinks in them. There is no host filesystem in a sandbox with no
  `mounts`. A mount that would contain `~/.terra` (this box's state or
  another's, and the kernel and agent every box boots) or **the terra binary
  itself** is refused when the recipe is read: those decide what the sandbox may
  mount and reach, what kernel it boots, and — for the binary, which an
  interactive or detached run re-executes to boot the VM — what the next run does
  at all, before there is a sandbox. They are not the sandbox's to write. A recipe
  *source* inside a share is allowed, because only `terra setup` reads one —
  and it asks first, showing what the recipe would grant, refusing outright where
  there is no terminal to ask on (`--trust-recipe` is the scripted yes). It asks
  about the first setup of a *new* box name too, since a box that does not exist
  yet has no recipe of its own to judge an edit against and `terra.yaml` lets a
  guest name one: the sibling box that granted the share is what answers.
- **`network.ports`** — a guest listener published on the host's `127.0.0.1`.
- **`allow: ["HOST_LOOPBACK[:PORT]"]`** — the only thing that reaches the
  machine terra is running on, together with a name a `hosts:` record resolves
  there. The host is not in the address namespace at all: no CIDR reaches it,
  `0.0.0.0/0` included, and neither does a mode's default reach.
- **`terra exec`** — one command in a running box, over a socket only the host
  can reach. It runs as whoever the workload runs
  as; `--root` runs it as root. That grants the *host* nothing new — the file
  service already writes any guest path as init, so a copy over a root-owned
  binary was always a way in — and it deliberately grants the *workload*
  nothing: a `sudo:` entry hands uid 1000 a standing escalation it can use
  whenever it likes, while an exec cannot be reached from inside the guest at
  all. Use `--root` for the things root is actually needed for (`apk add`,
  reading a root-owned log, `strace`) instead of widening `sudo:` for them.
- **`terra put` / `terra get`** — one file in or out, acting as guest root, over a socket only
  the host can reach. A file copied *out* keeps its permission bits so a script
  stays executable, minus setuid/setgid/sticky and group/world write: the guest
  chooses that file's contents, so it does not also get to leave a setuid binary
  — or one any other account can rewrite — owned by whoever ran the copy.
  Neither end follows a symlink at *any* component of the host path — the file
  itself or a directory above it — so a link the guest planted in a share fails
  with `ELOOP` instead of redirecting the copy into your `~/.ssh`. That is
  `openat2`'s `RESOLVE_NO_SYMLINKS`, which refuses the resolution in the kernel
  rather than checking a component and then opening it; `env_file:` is read the
  same way, for the same reason. (`O_NOFOLLOW` alone is not this: it covers the
  last component only, and the last component is not the shape of the attack.
  Off Linux — where no host boots a VM yet — the leaf is still all that is
  refused.) A copy out is capped at 8 GiB however long the guest says its file
  is, and both directions time out rather than waiting forever on a guest that
  has stopped answering.
- **`env:` values** — they travel in the boot plan over vsock and land in the
  workload's environment. They are never written to a file on either side, and
  the guest's own `/terra/README.md` names the variables without their values.

What does not cross it, in any configuration:

- **The host's own network, unless the recipe names it.** The egress floor is
  pinned to strict, so loopback, the host's LAN, every private range, link-local
  (cloud metadata) and the gateway's CGNAT range are unreachable by default —
  under `mode: unrestricted-public` too, and regardless of a learned DNS answer
  pointing there. That mode lifts the allow-list, not the floor, which is what
  its name says: *public* egress. An `allow` entry covering an address is the
  one thing that crosses it, because that is an operator writing it down.
- **The agent's vsock port.** The one port every session, `terra put`/`get` and
  `terra exec` connection arrives on is dialable from inside the guest (the
  kernel has vsock loopback), and its services act with init's privileges — so
  it accepts the host's CID and drops every other peer unread, and the agent
  claims it before any other guest code runs. The exec service matters most: a
  workload that owned the port could not gain privilege (it would be answering,
  not calling), but it could lie convincingly about what a `terra exec` found —
  in the one situation exec exists for, looking into a box you have stopped
  trusting.
- **The boot plan.** The host stops listening on the control port the moment the
  agent has dialled it, so nothing in the guest can ask for a second copy.

What is **not** a boundary, and should not be relied on as one:

- **Guest root.** `sudo:`, the `terri` user and the root-owned rootfs keep an
  agent from casually trashing its own box. They do not contain a hostile one —
  see the `sudo:` discussion in [recipe.md](recipe.md). The guest kernel is
  hardened against the workload-to-root hop (`kernel/terrarium-hardening.config`),
  but *hardened* is the right word and boundary is not: unprivileged user
  namespaces are available inside the box, because rootless `podman` is that
  mechanism rather than a consumer of it, so the distance from the workload user
  to guest root is a kernel bug. That is a deliberate trade, and it costs
  nothing the VM was not already covering.
- **Hooks.** `on_create`, `on_start` and `pre_stop` run as guest root, by design.
- **Running terra as host root.** Refused outright when any mount is writable.
  Root gets no idmap — real ids pass through virtiofs — so it acts as *real*
  root and the guest picks the owner, mode and setuid bit of everything it
  writes to a share — the sandbox inside out. Run terra as an unprivileged user in the
  `kvm` group (see [packaging/README.md](../packaging/README.md)), mark those
  mounts `readonly: true`, or set `TERRA_ALLOW_ROOT=1` if you genuinely mean it.
- **The recipe itself.** A recipe can mount any host path read-write and run any
  command in the hooks, so it is trusted input: read one before `terra setup`
  the way you would read a shell script before running it. This matters most for
  the obvious case — sandboxing a repository that ships its own recipe.
- **Your terminal.** A sandbox's output reaches it byte for byte, escape
  sequences and all — that is what makes a TUI inside the box work, and it is
  what joining a session is for. A workload can therefore drive
  whatever its reader's terminal emulator implements: OSC 52 clipboard writes,
  title set-and-report, hyperlinks. This is the same deal `ssh`, `docker attach`
  and `kubectl logs` offer, and the answer is the same one — a terminal that
  does not enable those sequences — but it is a surface the VM boundary does not
  cover, so it is named here rather than left implied.

On the host side, a box's own directory is `0700` and everything terra creates in
it is owner-only. The agent socket is bound by libkrun rather than terra, under a
process umask libkrun clears for its own reasons partway through a boot — so the
`0700` directory is what keeps another account off it, and its services act as
guest root, so that mode is not a detail. The log carries the guest's boot and
its hooks; the rootfs image carries everything the guest ever wrote.

`~/.terra` is `0700` on the same terms — and so are the box and cache
directories, each in its own right, since `config.yaml` can put either on a disk
mounted for everyone. Checked on every run rather than only when terra creates
them: a directory left open by an older version, or by a looser umask, is
tightened, and terra refuses to run if it cannot be. That is not
housekeeping — the reusable recipes live there, and a recipe is the policy for
what a box mounts and what it may reach, next to the cache holding the guest
kernel and the PID-1 agent every box on the machine boots. Another account able
to write there picks all of it.

What actually enforces the isolation is three dependencies, so it is worth being
explicit about how they are pinned: all three are git submodules pinned by commit
— libkrun (`vendor/libkrun`, an unpatched mirror of upstream), libkrunfw
(`vendor/libkrunfw`, pristine) and the egress gateway
([`smolvm-network`](https://github.com/cryi/smolvm), `vendor/smolvm`). The
gateway is vendored rather than pinned by Cargo revision because it is the code
that decides what a sandbox may reach: that belongs in the same review as the
policy that configures it, not behind a version bump — that review is what found
the two hard-floor gaps fixed upstream in `d2573ac`, which this pin includes. All
three checkouts are unmodified; see [`vendor/README.md`](../vendor/README.md). The
build inputs that are downloaded rather than pinned by commit — Alpine's
minirootfs, e2fsprogs, doas — are all verified against a SHA-256 in the Makefile.
