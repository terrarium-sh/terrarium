//! `terra logs` - print or follow the box's log, catching up across the roll
//! that may displace part of it. The writing side is [`crate::logs`]'s.

use crate::logs::roll_count;
use crate::state::BoxRef;
use crate::sys;
use std::path::Path;
use std::process::ExitCode;

pub fn run(
    args: &crate::cli::LogsArgs,
    name: Option<&str>,
    project_dir: &Path,
) -> anyhow::Result<ExitCode> {
    match write_log(args, name, project_dir) {
        // a broken pipe is the reader leaving, not an error.
        Err(e) if is_broken_pipe(&e) => Ok(ExitCode::SUCCESS),
        answered => answered,
    }
}

fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
}

/// A roll moves the window a follower has not reached yet into the rolled
/// generation; write it out from `read_to` and return the reopened live log,
/// `None` while the roll count has not moved. The count is marked only once a
/// roll's copy and truncation are both done, so a moved count is the whole
/// signal - without this the window would reach nobody, a silent hole.
fn catch_up_across_roll(
    bx: &BoxRef,
    read_to: u64,
    last_roll: &mut u64,
    out: &mut impl std::io::Write,
) -> anyhow::Result<Option<std::fs::File>> {
    use anyhow::Context as _;
    let rolls = roll_count(bx);
    if rolls == *last_roll {
        return Ok(None);
    }
    let missed_rolls = rolls.saturating_sub(*last_roll);
    *last_roll = rolls;
    // Exactly one generation is kept, so past one roll the offset points into a
    // generation that is gone and seeking the newest one at it would emit
    // somebody else's bytes as this reader's window. What is still on disk is
    // written whole instead, and the rest is named as lost.
    let resume_at = if missed_rolls > 1 {
        writeln!(
            out,
            "terra: (the log rolled {missed_rolls} times while this reader was behind - \
             what it had not read of the oldest generation is gone)"
        )
        .context("writing to stdout")?;
        0
    } else {
        read_to
    };
    // A missing rolled generation costs the window, not the follow.
    if let Ok(mut previous) = std::fs::File::open(bx.log_rolled())
        && std::io::Seek::seek(&mut previous, std::io::SeekFrom::Start(resume_at)).is_ok()
    {
        std::io::copy(&mut previous, out).context("streaming the rolled log")?;
    }
    let log = bx.log();
    std::fs::File::open(&log)
        .map(Some)
        .with_context(|| format!("reopening {}", log.display()))
}

fn write_log(
    args: &crate::cli::LogsArgs,
    name: Option<&str>,
    project_dir: &Path,
) -> anyhow::Result<ExitCode> {
    use anyhow::Context as _;
    use std::io::Write as _;
    let bx = &crate::resolve::resolve_pinned_box(project_dir, name)?;
    let log = bx.log();
    if !log.exists() {
        anyhow::bail!("no log for {bx} (no {})", log.display());
    }
    let mut out = std::io::stdout();
    // The rolled generation first, so the seam does not show. The roll count
    // is captured before that read, so a roll landing mid-read is still
    // caught by the loop below.
    let rolled = bx.log_rolled();
    let mut last_roll = roll_count(bx);
    if rolled.exists() {
        let mut previous = std::fs::File::open(&rolled)
            .with_context(|| format!("opening {}", rolled.display()))?;
        std::io::copy(&mut previous, &mut out).context("streaming the rolled log")?;
    }
    let mut f = std::fs::File::open(&log).with_context(|| format!("opening {}", log.display()))?;
    if !args.follow {
        std::io::copy(&mut f, &mut out).context("streaming log")?;
        out.flush().context("writing to stdout")?;
        return Ok(ExitCode::SUCCESS);
    }

    let mut read_to = 0u64;
    loop {
        let alive = bx.holder().holds();
        if let Some(fresh) = catch_up_across_roll(bx, read_to, &mut last_roll, &mut out)? {
            f = fresh;
        }
        let n = std::io::copy(&mut f, &mut out).context("streaming log")?;
        out.flush().context("writing to stdout")?;
        read_to = std::io::Seek::stream_position(&mut f).context("reading the log offset")?;
        if n == 0 {
            if !alive {
                return Ok(ExitCode::SUCCESS);
            }
            std::thread::sleep(sys::POLL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::roll_if_full;

    /// `terra logs -f` across a roll: by the time the follower notices, what it
    /// had not reached yet is in the rolled generation, so that is where the
    /// missing window is read from - starting at the offset the follower stood
    /// at. The roll count moving is the whole signal: it is marked only after
    /// the copy and the truncation, so a moved count means the window is in
    /// place - and an unmoved one, whatever the files look like mid-roll,
    /// means nothing has been displaced yet.
    #[test]
    fn following_across_a_roll_emits_the_window_the_roll_displaced() {
        use std::io::Read as _;
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(bx.dir()).unwrap();

        // A follower 8 bytes into a 12-byte log, which then rolls.
        std::fs::write(bx.log(), b"AAAABBBBCCCC").unwrap();
        let mut last_roll = roll_count(&bx);
        assert!(roll_if_full(&bx, 8), "over the cap: rolled");

        let mut shown = Vec::new();
        let fresh = catch_up_across_roll(&bx, 8, &mut last_roll, &mut shown).unwrap();
        assert_eq!(
            shown, b"CCCC",
            "the window between the follower and the roll"
        );
        let mut live = String::new();
        fresh
            .expect("the live file must be reopened after a roll")
            .read_to_string(&mut live)
            .unwrap();
        assert!(
            live.starts_with("terra: rolled at"),
            "and it is picked up from the start: {live}"
        );

        // A log that only grew is no roll: nothing is re-emitted, and the
        // follower keeps the handle - and the offset - it already had.
        std::fs::write(bx.log(), b"grown, and then some more").unwrap();
        let mut quiet = Vec::new();
        assert!(
            catch_up_across_roll(&bx, 8, &mut last_roll, &mut quiet)
                .unwrap()
                .is_none()
        );
        assert!(quiet.is_empty());

        // Mid-roll: the copy is done and the truncation is not, so nothing has
        // moved and every byte is still where the follower left it. The count
        // is marked last, which is what keeps this from re-emitting the log.
        std::fs::write(bx.log_rolled(), b"copied, not yet truncated").unwrap();
        let mut early = Vec::new();
        assert!(
            catch_up_across_roll(&bx, 8, &mut last_roll, &mut early)
                .unwrap()
                .is_none(),
            "a roll was acted on before it had displaced anything"
        );
        assert!(early.is_empty());

        // The roll the live log's length cannot show: it happened, and the log
        // grew back past the follower's offset before the next poll. The count
        // still says so, and without it those bytes reach nobody.
        std::fs::write(bx.log(), b"AAAABBBBCCCCDDDD").unwrap();
        assert!(roll_if_full(&bx, 8));
        std::fs::write(bx.log(), b"regrown well past the offset").unwrap();
        let mut displaced = Vec::new();
        let fresh = catch_up_across_roll(&bx, 8, &mut last_roll, &mut displaced).unwrap();
        assert_eq!(displaced, b"CCCCDDDD", "the window the roll displaced");
        assert!(fresh.is_some(), "the live file must be reopened");

        // …and each roll is caught up across exactly once, however long the
        // follower stays on it.
        let mut again = Vec::new();
        assert!(
            catch_up_across_roll(&bx, 12, &mut last_roll, &mut again)
                .unwrap()
                .is_none()
        );
        assert!(again.is_empty());

        // A rolled generation that is gone costs the window, not the follow:
        // the live file is still handed back.
        std::fs::write(bx.log(), b"AAAABBBBCCCC").unwrap();
        assert!(roll_if_full(&bx, 8));
        std::fs::remove_file(bx.log_rolled()).unwrap();
        let mut nothing = Vec::new();
        assert!(
            catch_up_across_roll(&bx, 8, &mut last_roll, &mut nothing)
                .unwrap()
                .is_some(),
            "a missing rolled generation must not end the follow"
        );
        assert!(nothing.is_empty());
    }

    /// Exactly one rolled generation is kept, so a reader that falls two rolls
    /// behind holds an offset into a generation that is gone - and the offset
    /// still lands inside the file that replaced it. Seeking there emits a
    /// stranger's bytes mid-line as if they were the window this reader
    /// missed, which is worse than a gap, because nothing about the output
    /// says it is wrong. The generation still on disk is written whole
    /// instead, and the part that cannot be recovered is said out loud.
    #[test]
    fn a_reader_more_than_one_roll_behind_is_told_rather_than_shown_the_wrong_window() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(bx.dir()).unwrap();

        // A reader 8 bytes into the first generation, which then rolls twice.
        std::fs::write(bx.log(), b"AAAABBBBCCCC").unwrap();
        let mut last_roll = roll_count(&bx);
        assert!(roll_if_full(&bx, 8));
        std::fs::write(bx.log(), b"SECOND-GENERATION-INTACT").unwrap();
        assert!(roll_if_full(&bx, 8));

        let mut shown = Vec::new();
        let fresh = catch_up_across_roll(&bx, 8, &mut last_roll, &mut shown).unwrap();
        let shown = String::from_utf8(shown).unwrap();
        assert!(
            shown.contains("SECOND-GENERATION-INTACT"),
            "the generation that is still there was cut at an offset belonging \
             to the one that is gone: {shown}"
        );
        assert!(
            shown.contains("rolled 2 times"),
            "the window that cannot be recovered goes unmentioned: {shown}"
        );
        assert!(fresh.is_some(), "the live file must still be reopened");

        // …and the reader is caught up: the next look at an unmoved count is
        // quiet, so the note is written once per gap rather than per poll.
        let mut again = Vec::new();
        assert!(
            catch_up_across_roll(&bx, 0, &mut last_roll, &mut again)
                .unwrap()
                .is_none()
        );
        assert!(again.is_empty());
    }
}
