//! The box's one rolling log - terra's, libkrun's and the gateway's
//! diagnostics, and the guest console (the VM's serial line: kernel, agent,
//! hooks). The workload's terminal is not in it - that is the guest agent's
//! session mux, live rather than recorded.

use crate::state::BoxRef;
use crate::sys;
use std::io::Write;
use std::str::FromStr;
use std::time::Duration;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

const ROLL_CAP_BYTES: u64 = 32 << 20;

const ROLL_CHECK_INTERVAL: Duration = Duration::from_millis(250);

fn default_filter() -> Targets {
    Targets::new()
        .with_default(tracing::Level::WARN)
        .with_target("smolvm_network", tracing::Level::DEBUG)
}

pub fn init() {
    let spec = std::env::var("RUST_LOG").ok();
    let asked = spec.as_deref().and_then(|s| match Targets::from_str(s) {
        Ok(filter) => Some(filter),
        Err(e) => {
            eprintln!(
                "terra: warning: RUST_LOG ('{s}') is not a filter this understands ({e}) - \
                 using the default (warn, and the egress gateway at debug)"
            );
            None
        }
    });

    let defaulted = asked.is_none();
    let filter = asked.unwrap_or_else(default_filter);

    // Through `stderr` rather than a handle of its own, so a roll - which
    // repoints that descriptor - carries this with it.
    let installed = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(std::io::stderr),
        )
        .with(filter)
        .try_init()
        .is_ok();

    // libkrun logs through the `log` facade at the subscriber's maximum level;
    // its per-frame debug sites would flood an unasked-for default, so the
    // default is pinned back to warn - records under it are never built at
    // all, not built for a filter to drop.
    if installed && defaulted {
        log::set_max_level(log::LevelFilter::Warn);
    }
}

pub fn open_for_a_run(bx: &BoxRef) -> anyhow::Result<std::fs::File> {
    use anyhow::Context as _;
    let path = bx.log();
    let log =
        sys::open_owner_only(&path).with_context(|| format!("opening log {}", path.display()))?;

    // `open_owner_only`'s mode applies only when it creates the file, so a log
    // left loose by an earlier run is tightened here instead.
    sys::set_open_file_mode(&log, 0o600);

    // separate runs
    let _ = writeln!(&log, "\n===== terra: {bx} =====");
    Ok(log)
}

pub fn roll_in_background(bx: &BoxRef) {
    let bx = bx.clone();
    std::thread::spawn(move || {
        loop {
            roll_if_full(&bx, ROLL_CAP_BYTES);
            std::thread::sleep(ROLL_CHECK_INTERVAL);
        }
    });
}

/// Copy-truncate, not the cheaper rename: libkrun dups the console descriptor
/// for the VM's life, so a rename would strand it in a generation the next
/// roll overwrites. Every writer is `O_APPEND`, so the truncation puts them
/// all back at zero with no hole.
pub(crate) fn roll_if_full(bx: &BoxRef, cap: u64) -> bool {
    let log = bx.log();
    if !std::fs::metadata(&log).is_ok_and(|m| m.len() > cap) {
        return false;
    }
    if std::fs::copy(&log, bx.log_rolled()).is_err() {
        return false;
    }
    // Bytes written between the copy and this truncation are lost -
    // sub-millisecond on a diagnostic log. Closing the gap would need every
    // writer funnelled through one descriptor terra owns.
    let Ok(fresh) = sys::open_owner_only(&log) else {
        return false;
    };
    if fresh.set_len(0).is_err() {
        return false;
    }
    let _ = writeln!(
        &fresh,
        "terra: rolled at {} MiB - what came before is in {}",
        cap >> 20,
        bx.log_rolled().display()
    );
    // The mark goes last, after the copy and the truncation - a follower
    // acts on the mark alone. A mark that cannot be written costs a follower
    // the bytes around this roll, just as a rolled generation that is gone
    // does.
    if let Ok(marks) = sys::open_owner_only(&bx.log_rolls()) {
        let _ = (&marks).write_all(b"+");
    }
    true
}

pub(crate) fn roll_count(bx: &BoxRef) -> u64 {
    std::fs::metadata(bx.log_rolls()).map_or(0, |m| m.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs are kept end to end: a new one continues the log it finds - and the
    /// generation rolled off it - with a mark of its own between them. The log
    /// used to be emptied per boot, which left a box crashlooping under a
    /// service manager with only whichever crash happened to be last.
    #[test]
    fn a_new_run_continues_the_log_it_finds() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(bx.dir()).unwrap();

        let first = open_for_a_run(&bx).unwrap();
        writeln!(&first, "the run before").unwrap();
        // As a roll would have left it, mid-run.
        std::fs::write(bx.log_rolled(), b"older still\n").unwrap();

        let second = open_for_a_run(&bx).unwrap();
        writeln!(&second, "this run").unwrap();

        let live = std::fs::read_to_string(bx.log()).unwrap();
        assert!(live.contains("the run before"), "{live}");
        assert!(live.contains("this run"), "{live}");
        assert_eq!(
            live.matches("===== terra:").count(),
            2,
            "one mark per run, and nothing else separates them: {live}"
        );
        assert!(
            live.find("the run before") < live.find("this run"),
            "runs are appended in the order they ran: {live}"
        );
        assert!(
            bx.log_rolled().exists(),
            "the rolled generation is history too - it outlives the run that wrote it"
        );
    }

    /// A roll keeps what it displaces, and - the reason it copies rather than
    /// renames - a descriptor opened before it keeps writing to the live file
    /// afterwards. libkrun holds exactly such a descriptor for the guest
    /// console: under a rename it would spend the rest of the VM's life writing
    /// into a generation the next roll overwrites.
    #[test]
    fn rolling_keeps_the_generation_it_displaces() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(bx.dir()).unwrap();
        // Through `open_owner_only`, because it is `O_APPEND` that puts this
        // handle back at zero after the truncation instead of leaving a hole.
        let console = sys::open_owner_only(&bx.log()).unwrap();
        (&console).write_all(&[b'Q'; 4096]).unwrap();

        assert!(!roll_if_full(&bx, 8192), "under the cap: left alone");
        assert_eq!(std::fs::metadata(bx.log()).unwrap().len(), 4096);
        assert!(!bx.log_rolled().exists());
        assert_eq!(roll_count(&bx), 0, "no roll, no mark");

        assert!(roll_if_full(&bx, 1024), "over the cap: rolled");
        assert_eq!(
            std::fs::read(bx.log_rolled()).unwrap(),
            vec![b'Q'; 4096],
            "the rolled generation must be kept whole"
        );
        assert_eq!(
            roll_count(&bx),
            1,
            "the roll is marked once both halves are done"
        );
        // The live file was emptied, and says where the rest went.
        let live = std::fs::read_to_string(bx.log()).unwrap();
        assert!(live.contains("what came before is in"), "{live}");
        assert!(live.contains("terra.log.1"), "{live}");

        // The descriptor taken before the roll still writes to the live file,
        // and appends rather than punching a 4 KiB hole at the front of it.
        writeln!(&console, "after the roll").unwrap();
        let live = std::fs::read_to_string(bx.log()).unwrap();
        assert!(
            live.contains("after the roll"),
            "a descriptor from before the roll lost the live file: {live}"
        );
        assert!(!live.contains('\0'), "the truncation left a hole: {live:?}");

        // A second roll replaces the previous generation; exactly one is kept.
        std::fs::write(bx.log(), vec![b'Z'; 4096]).unwrap();
        assert!(roll_if_full(&bx, 1024), "rolled again");
        assert_eq!(std::fs::read(bx.log_rolled()).unwrap(), vec![b'Z'; 4096]);
        assert_eq!(roll_count(&bx), 2);

        // A log that is not there at all is not an error.
        let absent = BoxRef::from_state_dir(dir.path().join("none"), dir.path());
        assert!(!roll_if_full(&absent, 0));
    }
}
