use std::path::PathBuf;

use terra_runtime::engine::{device_engine, policy_engine, precompile_component};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut paths = std::env::args_os().skip(1);
    let input = PathBuf::from(paths.next().ok_or("missing component input")?);
    let output = PathBuf::from(paths.next().ok_or("missing artifact output")?);
    let engine = match paths.next() {
        None => device_engine()?,
        Some(flag) if flag == "--policy" => policy_engine()?,
        Some(_) => return Err("usage: precompile-component INPUT OUTPUT [--policy]".into()),
    };
    if paths.next().is_some() {
        return Err("usage: precompile-component INPUT OUTPUT [--policy]".into());
    }
    let artifact = precompile_component(&engine, &std::fs::read(input)?)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if std::fs::read(&output).ok().as_deref() != Some(artifact.as_slice()) {
        std::fs::write(output, artifact)?;
    }
    Ok(())
}
