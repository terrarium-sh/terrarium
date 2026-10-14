//! Generates each role's syscall allowlist by statically scanning a binary built for that role.

mod flow;
mod image;
mod isa;
mod scan;

use anyhow::{Context as _, Result, bail, ensure};
use std::path::{Path, PathBuf};
use terra_build::seccomp::{Architecture, Role};
use terra_build::seccomp_policy::{Policy, RolePolicy, policy_path, read_policy, render_policy};

/// Writes, or with `--check` verifies, the checked-in seccomp allowlists for a target.
#[derive(clap::Parser)]
pub struct Options {
    /// The Rust target the binaries were built for, such as `x86_64-unknown-linux-musl`.
    #[arg(long)]
    pub target: String,
    #[arg(long)]
    pub supervisor: PathBuf,
    #[arg(long)]
    pub vm: PathBuf,
    #[arg(long)]
    pub network: PathBuf,
    /// The shipped executable, whose constructors each role binary must also contain.
    #[arg(long)]
    pub executable: PathBuf,
    /// Compare with the checked-in policy instead of writing it, and fail on any difference.
    #[arg(long)]
    pub check: bool,
}

impl Options {
    fn binary(&self, role: Role) -> &Path {
        match role {
            Role::Supervisor => &self.supervisor,
            Role::Vm => &self.vm,
            Role::Network => &self.network,
        }
    }
}

pub fn run(options: &Options) -> Result<()> {
    let architecture = Architecture::from_triple(&options.target).map_err(anyhow::Error::msg)?;
    // Constructors run in every role process, so each role binary's scan must include them.
    let constructors = image::constructors(&options.executable)?;
    let mut policy = Policy::new();
    for role in Role::ALL {
        let binary = options.binary(role);
        let scanned = scan::scan(binary)?;
        ensure!(
            scanned.architecture == architecture,
            "{} is not built for {architecture:?}",
            binary.display()
        );
        let missing: Vec<_> = constructors.difference(&scanned.constructors).collect();
        ensure!(
            missing.is_empty(),
            "{} lacks constructors the executable runs before main: {missing:?}",
            binary.display()
        );
        let syscalls = scanned
            .syscalls
            .iter()
            .map(|&number| {
                u32::try_from(number)
                    .ok()
                    .and_then(|number| architecture.name_syscall(number))
                    .map(str::to_owned)
                    .with_context(|| {
                        format!("{}: unknown syscall number {number}", binary.display())
                    })
            })
            .collect::<Result<_>>()?;
        let ioctls = scanned
            .ioctls
            .iter()
            .map(|&request| u32::try_from(request))
            .collect::<Result<_, _>>()?;
        policy.insert(role, RolePolicy { syscalls, ioctls });
    }
    let path = policy_path(Path::new(env!("CARGO_MANIFEST_DIR")), &options.target);
    if !options.check {
        std::fs::write(&path, render_policy(&options.target, &policy))
            .with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", path.display());
        return Ok(());
    }
    let committed = read_policy(&path, &options.target).map_err(anyhow::Error::msg)?;
    let differences = describe_differences(&committed, &policy);
    if !differences.is_empty() {
        bail!(
            "{} is out of date; run `make policy` and review the change:\n  {}",
            path.display(),
            differences.join("\n  ")
        );
    }
    println!("{} matches the role binaries", path.display());
    Ok(())
}

fn describe_differences(committed: &Policy, generated: &Policy) -> Vec<String> {
    let empty = RolePolicy::default();
    let mut differences = Vec::new();
    for role in Role::ALL {
        let old = committed.get(&role).unwrap_or(&empty);
        let new = generated.get(&role).unwrap_or(&empty);
        for name in new.syscalls.difference(&old.syscalls) {
            differences.push(format!("{}: + {name}", role.name()));
        }
        for name in old.syscalls.difference(&new.syscalls) {
            differences.push(format!("{}: - {name}", role.name()));
        }
        for request in new.ioctls.difference(&old.ioctls) {
            differences.push(format!("{}: + ioctl {request:#010x}", role.name()));
        }
        for request in old.ioctls.difference(&new.ioctls) {
            differences.push(format!("{}: - ioctl {request:#010x}", role.name()));
        }
    }
    differences
}
