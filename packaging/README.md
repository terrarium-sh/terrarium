# Running terra under systemd

`terra <box> --foreground` runs the microVM in its own process and exits when the
VM stops — so it maps cleanly onto a `Type=exec` service, the same shape podman
uses. The templated unit [`terra@.service`](terra@.service) is two steps, because
only `setup` reads a recipe *path* and a boot takes a box *name*:

```
systemctl start terra@pi-dev
  # -> terra /var/lib/terra/.terra/pi-dev.yaml setup --trust-recipe
  #    terra pi-dev --foreground
```

The instance name is the recipe file's stem, so the box is named `%i` too. Setup
runs on every start, which is what makes editing the recipe and restarting the
service mean something; on an unchanged recipe it pins nothing and re-bakes
nothing.

A box lives at `~/.terra/box/<slug of its project directory>/<name>`, so what the
unit's `WorkingDirectory` decides is the slug — which is why it carries `%i`. Do
not drop it: with a shared working directory both instances resolve to the *same*
box, and because setup only builds a guest filesystem when none exists, starting
the second recipe would rewrite that box's recipe and then boot the filesystem
the first one's workload had been writing to.

## What terra needs from the environment

These are the requirements the unit satisfies; anything stricter breaks it.

| Requirement | Why | Unit knob |
|---|---|---|
| `/dev/kvm` read-write | libkrun runs the VM on KVM | `SupplementaryGroups=kvm`, `DeviceAllow=/dev/kvm rw`, no `PrivateDevices` |
| W+X memory | KVM guest memory mappings | `MemoryDenyWriteExecute=no` |
| Real host network | the in-process egress proxy opens host sockets | no `PrivateNetwork`, no `IPAddressDeny` |
| Writable `$HOME/.terra` | cache of the guest kernel and boot volume (unpacked once, shared by every box), plus the box state | `StateDirectory=terra` + `Environment=HOME=%S/terra` |
| A recipe to boot | `~/.terra/%i.yaml`, read by the `ExecStartPre` setup | yours to install; see below |

The host needs no namespace privileges of its own: share ownership is remapped
*inside* the guest (the agent unshares a user namespace there), so nothing on
this side calls `unshare`.

Running as root instead of the `terra` user boots, but it is **not** an equal
option and should not be the default. At uid 0 virtiofs serves the guest with
real root authority: on every read-write mount the guest picks the owner, the
mode and the setuid bit of anything it writes, and those land on the host as
root. A sandbox is then one `chmod 4755` away from leaving a setuid-root binary
in a directory you share. terra warns about this at boot. Use the unprivileged
`terra` user in the `kvm` group; if you must run as root, keep every mount
`readonly: true`.

## One-time host setup

```sh
# Install the binary and the unit.
install -m0755 dist/terra /usr/local/bin/terra
install -m0644 packaging/terra@.service /etc/systemd/system/

# Man pages (generated from the CLI at build time).
install -m0644 packaging/man/*.1 /usr/local/share/man/man1/

# Dedicated account in the kvm group (state lives in /var/lib/terra via StateDirectory).
useradd --system --home-dir /var/lib/terra --shell /usr/sbin/nologin --groups kvm terra

# The recipe the instance boots. ~/.terra is terra's own directory, which no box
# can share — which is what lets the unit pass --trust-recipe honestly.
install -d -o terra -g terra -m0700 /var/lib/terra/.terra
install -o terra -g terra -m0600 pi-dev.yaml /var/lib/terra/.terra/

systemctl daemon-reload
systemctl enable --now terra@pi-dev
journalctl -u terra@pi-dev -f
```

The recipe should define a `workload:` — headless there's no interactive shell to
fall back to. Its `mounts:` decide what of the host is exposed at `/work`. Keep
it out of any directory the box shares read-write: a recipe a guest could rewrite
is one terra stops to ask about, and the unit has no terminal to be asked on.

## Graceful stop

`systemctl stop` (SIGTERM) shuts the guest down orderly: terra writes one byte on
the guest's control connection, the agent stops the workload (SIGTERM, then
SIGKILL if it is still there five seconds later — an interactive shell ignores
SIGTERM) and runs the recipe's `pre_stop` hooks, then the VM exits. Give
`pre_stop` enough room with `TimeoutStopSec` (30s in the unit); after that systemd
escalates to SIGKILL, which still leaves no orphan (the VM runs inside terra's
process).

## Where the output goes

A `--foreground` boot splits it in two, and the split is the same one terra makes
everywhere — *what is it doing* from *why is it broken*:

- **The journal** gets the workload's terminal and the guest console (kernel,
  agent, `on_create`/`on_start`/`pre_stop` hooks). `journalctl -u terra@pi-dev`.
- **`terra logs pi-dev`** gets terra's own diagnostics, libkrun's, and the
  gateway's account of what egress it refused.

The console is output-only here — the host gives the guest `/dev/null` for
console input, so nothing typed at the service reaches the workload. To steer it,
attach from any terminal: `terra pi-dev` joins the session, forwards your keys to
the workload's PTY, and `Ctrl-\` leaves without stopping it. Every attached
client shares one view, so this composes with a person already watching.
