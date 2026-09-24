# Terrarium sandbox

You are inside a Terrarium micro-VM: an isolated Linux guest (Alpine). The
facts that matter for working here:

- You run as {who}.
- The root filesystem is a private disk image. It PERSISTS across restarts of
  this sandbox (only `terra rm` on the host clears it). Its size is capped, so
  it can fill up: writes past the cap fail with ENOSPC.
- Only the `mounts` listed below are shared with the host. Everything else you
  write stays inside the sandbox.
- Network egress is filtered (see Network below). When an address is
  unreachable, the egress policy - not an outage - is the likely reason.

## Workload

The command this sandbox runs:

`{cmd}`

## Configuration (resolved)

```yaml
{yaml}```

What each option means from inside the sandbox:

- `hw` - your resources; `rootfs_mib` caps the root filesystem.
- `mounts` - host directories shared into the sandbox: files under a `guest`
  path are visible on the host at its `host` path, and vice versa. A
  `readonly: true` mount rejects writes. Nothing outside these mounts reaches
  the host filesystem.
- `volumes` - bounded scratch disks: each an ext4 image of `size_mib`, mounted
  at its `guest` path, persistent across restarts of this box.
- `env` - variable names exported to you. Values are deliberately not written
  into this file; read them from your environment.
- `sudo` - the commands you may run as root via `doas` (or `sudo`). Every
  other command is denied root.
- `hooks` - `on_create` was baked into this filesystem once; `on_start` ran
  before your workload; `pre_stop` runs on an orderly stop.
- `daemons` - background commands started with you, restarted on failure until
  the box stops.
- `network` - the egress policy (next section).

## Network

Egress policy: {egress}.

- Guest address `{ip}/{prefix}`, gateway `{gw}`, DNS `{dns}`.
- All traffic goes through a filtering gateway; there is no other route out.
- IPs collected from host interfaces at VM startup, including public IPs, and
  private address ranges require explicit `allow` rules.
  `HOST_LOOPBACK` in `allow` grants access to services on the host's loopback
  interface (or use a `hosts:` name pointing there that `allow` covers).
- `mode: allowlist` - only what the `allow` rules cover connects, and only the
  names they list resolve. With no rules at all, nothing gets out - not even
  DNS queries.
- `mode: unrestricted-public` - public destinations are reachable, including
  public addresses on a LAN, except the collected host interface IPs. Filtering
  uses addresses, not network location; a public NAT address forwarding to the
  host may still be reachable.
- A `hosts:` record only pins where a name resolves. Whether that address may
  be reached is still decided by `allow`, as for any other name.
