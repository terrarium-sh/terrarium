fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::var("TARGET")?;
    println!("cargo:rustc-env=TERRA_BUILD_TARGET={target}");
    if std::env::var("CARGO_CFG_TARGET_OS")? == "linux" {
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH")?;
        compile_default_seccomp(&arch)?;
        let asset = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../build/bwrap-{arch}"));
        let metadata = std::fs::metadata(&asset).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "{} is missing; run `make ARCH={arch} build/bwrap-{arch}`: {error}",
                    asset.display()
                ),
            )
        })?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(std::io::Error::other(format!(
                "{} is not a built Bubblewrap executable; run `make ARCH={arch} build/bwrap-{arch}`",
                asset.display()
            ))
            .into());
        }
        println!("cargo:rerun-if-changed={}", asset.display());
        println!("cargo:rustc-env=TERRA_BWRAP_BIN={}", asset.display());
    }
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    println!("cargo:rerun-if-changed=../../.git/refs/tags");

    let Some(hash) = git(&["rev-parse", "--short", "HEAD"]) else {
        println!(
            "cargo:rustc-env=TERRA_VERSION={}",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    };

    let version = match git(&["describe", "--tags", "--exact-match"]) {
        Some(tag) => tag.strip_prefix('v').unwrap_or(&tag).to_owned(),
        None => "dev".to_owned(),
    };

    println!("cargo:rustc-env=TERRA_VERSION={version}+{hash}");
    Ok(())
}

fn compile_default_seccomp(arch: &str) -> Result<(), Box<dyn std::error::Error>> {
    const LOAD_WORD: u16 = 0x20;
    const JUMP_EQUAL: u16 = 0x15;
    const JUMP_BITS_SET: u16 = 0x45;
    const RETURN: u16 = 0x06;
    const KILL_PROCESS: u32 = 0x8000_0000;
    const DENY_EPERM: u32 = 0x0005_0001;
    const ALLOW: u32 = 0x7fff_0000;

    let audit_arch = match arch {
        "x86_64" => 0xc000_003e,
        "aarch64" => 0xc000_00b7,
        _ => return Err("VM execution requires Linux x86_64 or aarch64".into()),
    };
    if std::env::var("CARGO_CFG_TARGET_ENDIAN")? != "little" {
        return Err("VM execution requires a little-endian Linux target".into());
    }
    let denied_syscalls = [
        ("ptrace", 101, 117),
        ("bpf", 321, 280),
        ("perf_event_open", 298, 241),
        ("kexec_load", 246, 104),
        ("kexec_file_load", 320, 294),
        ("init_module", 175, 105),
        ("finit_module", 313, 273),
        ("delete_module", 176, 106),
        ("reboot", 169, 142),
        ("add_key", 248, 217),
        ("request_key", 249, 218),
        ("keyctl", 250, 219),
    ];
    let mut bpf = Vec::new();
    append_instruction(&mut bpf, LOAD_WORD, 0, 0, 4);
    append_instruction(&mut bpf, JUMP_EQUAL, 1, 0, audit_arch);
    append_instruction(&mut bpf, RETURN, 0, 0, KILL_PROCESS);
    append_instruction(&mut bpf, LOAD_WORD, 0, 0, 0);
    if arch == "x86_64" {
        append_instruction(&mut bpf, JUMP_BITS_SET, 0, 1, 0x4000_0000);
        append_instruction(&mut bpf, RETURN, 0, 0, KILL_PROCESS);
    }
    for (_, x86_64, aarch64) in denied_syscalls {
        let syscall = if arch == "x86_64" { x86_64 } else { aarch64 };
        append_instruction(&mut bpf, JUMP_EQUAL, 0, 1, syscall);
        append_instruction(&mut bpf, RETURN, 0, 0, DENY_EPERM);
    }
    append_instruction(&mut bpf, RETURN, 0, 0, ALLOW);
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR is missing")?);
    std::fs::write(output.join("default-seccomp.bpf"), bpf)?;
    Ok(())
}

fn append_instruction(bpf: &mut Vec<u8>, code: u16, jump_true: u8, jump_false: u8, value: u32) {
    bpf.extend_from_slice(&code.to_le_bytes());
    bpf.extend_from_slice(&[jump_true, jump_false]);
    bpf.extend_from_slice(&value.to_le_bytes());
}

fn git(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git").args(args).output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (output.status.success() && !stdout.is_empty()).then_some(stdout)
}
