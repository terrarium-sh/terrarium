//! The command line, as clap types. `examples/gen-docs.rs` (`make man`) renders
//! the man pages and completions from these, so this is the single source of
//! truth for both.

use clap::{Args, CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
use terra_protocol::DEFAULT_STOP_GRACE_SECS;

#[derive(Parser, Debug)]
#[command(
    name = "terra",
    version = env!("CARGO_PKG_VERSION"),
    about = "Launch isolated microVMs for AI agents",
    long_about = "Launch isolated microVMs for AI agents.\n\n\
                  The box comes first, always: `terra [BOX]` starts it, or attaches if \
                  it is already up. A verb after the box names one operation on it \
                  instead - `terra dev stop`, `terra dev get /etc/x .` - and every verb \
                  defaults to this directory's only box. With a box already up and \
                  neither a terminal to attach from nor `-d`, terra exits 125.",
    after_long_help = "EXAMPLES:\n    \
                       terra dev                   Start this directory's box `dev`, or attach\n    \
                       terra dev exec -- ls        Run a command in the running box\n    \
                       terra ./pi-dev.yaml setup   Set up a box from a recipe\n    \
                       terra dev logs -f           Follow the box's log"
)]
pub struct Cli {
    /// Box name. Default: this directory's only box.
    #[arg(value_name = "BOX")]
    pub name: Option<String>,
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
    #[command(flatten)]
    pub boot: BootArgs,
    /// The project directory whose boxes to address (default: the current one).
    #[arg(long, value_name = "DIR", global = true)]
    pub project: Option<PathBuf>,
}

impl Cli {
    #[must_use]
    fn has_boot_flags(&self) -> bool {
        let BootArgs {
            root,
            detach,
            foreground,
            command,
            agent,
        } = &self.boot;
        *root || *detach || *foreground || agent.agent_timeout.is_some() || !command.is_empty()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let Some(cmd) = &self.cmd else {
            return Ok(());
        };
        let verb = cmd.verb();
        let boot_hint = if cmd.takes_the_box() {
            format!(
                "or run the box first (`terra {box_name} -d`) and then `terra {box_name} {verb}`",
                box_name = self.name.as_deref().unwrap_or("<box>"),
            )
        } else {
            "or run `terra ls` without a box".to_owned()
        };
        anyhow::ensure!(
            !self.has_boot_flags(),
            "the boot flags shape a boot, and `{verb}` is not one - drop them, {boot_hint}",
        );
        anyhow::ensure!(
            cmd.takes_the_box() || self.name.is_none(),
            "`{verb}` takes no box before it - write `terra {verb}`",
        );
        Ok(())
    }
}

/// The box-first fix for a verb-first spelling like `terra stop dev`.
fn build_reversal_hint(typed: &[String]) -> Option<String> {
    let [verb, name] = typed else { return None };
    crate::resolve::BoxArg::parse(name).ok()?;
    let command = Cli::command();
    let subcommand = command.find_subcommand(verb)?;
    let cmd = Cli::try_parse_from(["terra", verb]).ok()?.cmd?;
    (cmd.takes_the_box() && subcommand.get_positionals().count() == 0)
        .then(|| format!("terra: the box comes before the verb - `terra {name} {verb}`"))
}

#[must_use]
pub fn parse_or_exit() -> Cli {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(reported) => {
            let typed: Vec<String> = std::env::args_os()
                .skip(1)
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            let Some(hint) = build_reversal_hint(&typed) else {
                reported.exit()
            };
            let _ = reported.print();
            eprintln!("{hint}");
            std::process::exit(2)
        }
    };
    if let Err(refused) = cli.validate() {
        Cli::command()
            .error(clap::error::ErrorKind::ArgumentConflict, refused)
            .exit()
    }
    cli
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Set up a box for this directory: read a recipe, pin it, build the guest
    /// filesystem, and bake `on_create`. Safe to run again.
    ///
    /// The box before it may be a recipe *path* as well as a name, the box then
    /// taking the file's stem: `terra ./pi-dev.yaml setup`.
    Setup(SetupArgs),
    /// Run a command in a running box, on a terminal of its own - a second
    /// process beside the workload, not a second view of it.
    ///
    /// Runs as whoever the workload runs as; `--root` runs it as root instead.
    /// That is the difference from a `sudo:` entry, which hands the same power
    /// to the workload permanently.
    ///
    /// Its exit status is this command's.
    Exec(ExecArgs),
    /// Copy one file from the host into the box.
    Put(CopyArgs),
    /// Copy one file out of the box onto the host. A destination directory
    /// keeps the file's own name.
    Get(CopyArgs),
    /// Show a box's host diagnostics, rotated as it grows. `--diagnostics` shows guest VM
    /// diagnostics instead; both are replayed after a failed boot. The workload's
    /// terminal goes to the session - attach to the box to see it live.
    Logs(LogsArgs),
    /// List the clients attached to the box's session: the ids `terra <box>
    /// detach` takes, and the terminal size each one reported. The shared
    /// view fits the tightest client, so one that stopped reading keeps it
    /// small until it is detached.
    Sessions(SessionsArgs),
    /// Drop one attached client of the box's session - or every one of them.
    /// The client's connection is closed and its terminal restored, as if the
    /// detach key had been pressed.
    Detach(DetachArgs),
    /// Print the fully-resolved config a boot would use: the box's pinned
    /// recipe, or - for a box not set up yet, or a recipe named by path - the
    /// recipe that would be pinned.
    ///
    /// For review only - `env:` values are printed as a placeholder unless
    /// `--with-env-values`, and paths as the absolute ones they resolved to on
    /// this machine, so it is not a recipe you can pin back.
    Show(ShowArgs),
    /// List this directory's boxes and what state each is in - or, with
    /// `--all`, every box on this machine.
    #[command(alias = "ps")]
    Ls(LsArgs),
    /// Stop a running box: the guest runs `pre_stop`, then the VM exits.
    Stop(StopArgs),
    /// The box's storage - its guest filesystem and volume images.
    Storage(StorageArgs),
    /// Throw a box away: its guest filesystem, volumes, logs and sockets. The
    /// recipe is kept, so `terra <box>` can build it again from scratch.
    Rm(RmArgs),
}

impl Cmd {
    fn verb(&self) -> &'static str {
        match self {
            Self::Setup(_) => "setup",
            Self::Exec(_) => "exec",
            Self::Put(_) => "put",
            Self::Get(_) => "get",
            Self::Logs(_) => "logs",
            Self::Sessions(_) => "sessions",
            Self::Detach(_) => "detach",
            Self::Show(_) => "show",
            Self::Ls(_) => "ls",
            Self::Stop(_) => "stop",
            Self::Storage(_) => "storage",
            Self::Rm(_) => "rm",
        }
    }

    /// Whether `terra <box> <verb>` means anything for this verb.
    #[must_use]
    fn takes_the_box(&self) -> bool {
        match self {
            Cmd::Setup(_)
            | Cmd::Exec(_)
            | Cmd::Put(_)
            | Cmd::Get(_)
            | Cmd::Logs(_)
            | Cmd::Sessions(_)
            | Cmd::Detach(_)
            | Cmd::Show(_)
            | Cmd::Stop(_)
            | Cmd::Storage(_)
            | Cmd::Rm(_) => true,
            Cmd::Ls(_) => false,
        }
    }
}

#[derive(Args, Debug)]
pub struct SetupArgs {
    /// Pin the recipe without asking, even when a guest could have written
    /// it. Required when there is no terminal to ask on.
    #[arg(long)]
    pub trust_recipe: bool,
    /// Rebuild the guest filesystem from scratch, re-bake `on_create`, and
    /// remove the volume images the recipe no longer names.
    #[arg(long)]
    pub rebuild: bool,
    /// Run every refusal this setup would raise and stop before it changes
    /// anything: nothing is pinned, no filesystem is built, no hook runs.
    ///
    /// Exits 0 if the setup would go through, non-zero with the refusal if it
    /// would not - so a CI step is `terra <box> setup --dry-run`. The other two
    /// flags decide what a setup *does*, which is the half this skips, so
    /// neither can be written alongside it.
    #[arg(long, conflicts_with_all = ["rebuild", "trust_recipe"])]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Print the `env:` values too, instead of a placeholder. They are secrets
    /// often enough to be worth asking for: this output is made to be
    /// redirected to a file or pasted into a bug report.
    #[arg(long)]
    pub with_env_values: bool,
}

#[derive(Args, Debug)]
pub struct ExecArgs {
    /// Run as root instead of the workload's own user.
    #[arg(long)]
    pub root: bool,
    /// Give the command a terminal even when terra was not started at one -
    /// for a script driving something that only works on a PTY.
    #[arg(short = 't', long, conflicts_with = "no_tty")]
    pub tty: bool,
    /// Give the command pipes even when terra was started at a terminal, so
    /// its output is exactly what a redirect would capture.
    #[arg(short = 'T', long)]
    pub no_tty: bool,
    #[command(flatten)]
    pub agent: AgentTimeoutArg,
    /// The command to run, after `--`. argv is passed literally to the guest
    /// exec, so use `-- sh -c '…'` for a shell line.
    #[arg(last = true, required = true, value_name = "CMD")]
    pub command: Vec<String>,
}

impl ExecArgs {
    /// Whether the command gets a PTY.
    #[must_use]
    pub fn wants_a_terminal(&self, is_at_a_terminal: bool) -> bool {
        (is_at_a_terminal || self.tty) && !self.no_tty
    }
}

#[derive(Args, Debug)]
pub struct CopyArgs {
    /// Source path. The guest side is absolute; the host side is anything.
    pub src: String,
    /// Destination path.
    pub dst: String,
    #[command(flatten)]
    pub agent: AgentTimeoutArg,
}

/// `--agent-timeout`, one definition for the verbs that dial the live agent
/// (`exec`, `put`, `get`).
#[derive(Args, Debug)]
pub struct AgentTimeoutArg {
    /// Give up after this many seconds if the agent has not answered yet (it
    /// answers once the workload is up, so a boot or an `on_create` bake is
    /// waited out). Bounds only the wait for the agent, never the command's
    /// own runtime. Default: wait for as long as the box is running.
    #[arg(long, value_name = "SECS")]
    pub agent_timeout: Option<u64>,
}

const STOP_TEARDOWN_ALLOWANCE_SECS: u64 = 35;
const DEFAULT_STOP_WAIT_SECS: u64 = DEFAULT_STOP_GRACE_SECS + STOP_TEARDOWN_ALLOWANCE_SECS;

#[derive(Args, Debug)]
pub struct StopArgs {
    /// How long to wait in seconds for the guest to shut down before the
    /// VM is killed.
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_STOP_WAIT_SECS)]
    pub wait: u64,
}

#[derive(Args, Debug)]
pub struct RmArgs {
    /// Remove the recipe too, leaving nothing of the box at all.
    #[arg(long)]
    pub purge: bool,
    /// Remove it even while a VM is running: a graceful stop is asked for
    /// first, but the box is removed either way.
    #[arg(long)]
    pub force: bool,
    /// How long to wait in seconds for that graceful stop. Only means anything
    /// with `--force`, so clap refuses it on its own.
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_STOP_WAIT_SECS, requires = "force")]
    pub wait: u64,
}

#[derive(Args, Debug)]
pub struct StorageArgs {
    #[command(subcommand)]
    pub cmd: StorageCmd,
}

#[derive(Subcommand, Debug)]
pub enum StorageCmd {
    /// List the box's images: what each is sized to, what it costs on disk,
    /// and which the recipe no longer names.
    Show,
    /// Write the box's images to one file, to be imported into a box set up
    /// from the same recipe on another machine.
    ///
    /// The images only - the recipe is what makes a box, and it travels with
    /// the project. The box must not be running.
    Export(StorageFileArgs),
    /// Replace the box's images with those in a file `export` wrote. The box
    /// must be set up already, and must not be running.
    Import(StorageFileArgs),
    /// Remove the volume images the recipe no longer names. Their data goes
    /// with them.
    Prune,
}

#[derive(Args, Debug)]
pub struct StorageFileArgs {
    /// The artifact's path on the host.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

#[derive(Args, Debug)]
pub struct LsArgs {
    /// Every box on this machine instead, each with the directory it belongs
    /// to.
    #[arg(long)]
    pub all: bool,
    /// One box per line - state, name, directory, files - separated by tabs,
    /// with no prose around them. This is the format scripts may rely on; the
    /// human listing is prose and may change.
    #[arg(long)]
    pub tsv: bool,
}

#[derive(Args, Debug)]
pub struct LogsArgs {
    /// Follow the log as it grows.
    #[arg(short, long)]
    pub follow: bool,
    /// Show guest VM diagnostics instead of Terra's host log.
    #[arg(long)]
    pub diagnostics: bool,
}

#[derive(Args, Debug)]
pub struct SessionsArgs {
    #[command(flatten)]
    pub agent: AgentTimeoutArg,
}

#[derive(Args, Debug)]
pub struct DetachArgs {
    /// The client id `terra <box> sessions` printed.
    #[arg(
        value_name = "ID",
        required_unless_present = "all",
        conflicts_with = "all"
    )]
    pub id: Option<u64>,
    /// Detach every attached client instead of one by id.
    #[arg(long)]
    pub all: bool,
    #[command(flatten)]
    pub agent: AgentTimeoutArg,
}

#[derive(Args, Debug)]
pub struct BootArgs {
    /// Run the workload as root instead of the default `terri` (uid 1000).
    #[arg(long)]
    pub root: bool,

    /// Run headless in the background; manage with `terra <box> logs` and
    /// `terra <box> stop`.
    #[arg(short = 'd', long)]
    pub detach: bool,

    /// Run the VM in this process, in the foreground - for a service manager
    /// (systemd), which wants the VM as its own child and has no terminal to
    /// join.
    #[arg(long, conflicts_with = "detach")]
    pub foreground: bool,

    #[command(flatten)]
    pub agent: AgentTimeoutArg,

    /// Command to run instead of the recipe's `workload:`, after `--`. argv is
    /// passed literally to the guest exec, so use `-- sh -c '…'` for a shell
    /// line.
    #[arg(last = true, value_name = "CMD")]
    pub command: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name;
    use clap::{CommandFactory, Parser};
    use std::path::Path;

    #[test]
    fn bare_invocation_is_start() {
        let bare = Cli::parse_from(["terra"]);
        assert!(bare.cmd.is_none());
        assert!(bare.name.is_none());

        let named = Cli::parse_from(["terra", "pi-dev", "-d"]);
        assert!(named.cmd.is_none());
        assert_eq!(named.name.as_deref(), Some("pi-dev"));
        assert!(named.boot.detach);

        assert!(matches!(
            Cli::parse_from(["terra", "pi-dev", "setup"]).cmd,
            Some(Cmd::Setup(_))
        ));
        let Some(Cmd::Rm(rm_args)) = Cli::parse_from(["terra", "rm", "--purge"]).cmd else {
            panic!("expected rm")
        };
        assert!(rm_args.purge);
    }

    /// The box comes first and the verb second, and every verb that addresses
    /// one takes the same default - this directory's only box - so the name is
    /// read in exactly one place whatever follows it.
    #[test]
    fn the_box_comes_before_the_verb_and_is_always_optional() {
        for (argv, name) in [
            (vec!["terra", "dev", "stop"], Some("dev")),
            (vec!["terra", "stop"], None),
            (vec!["terra", "dev", "logs", "-f"], Some("dev")),
            (vec!["terra", "logs"], None),
            (vec!["terra", "dev", "sessions"], Some("dev")),
            (vec!["terra", "sessions"], None),
            (vec!["terra", "dev", "detach", "3"], Some("dev")),
            (vec!["terra", "detach", "3"], None),
            (vec!["terra", "detach", "--all"], None),
            (vec!["terra", "dev", "get", "/etc/x", "."], Some("dev")),
            (vec!["terra", "put", "./a", "/tmp/a"], None),
            (vec!["terra", "dev", "exec", "--", "ls"], Some("dev")),
            (vec!["terra", "dev", "show"], Some("dev")),
            (vec!["terra", "dev", "rm", "--purge"], Some("dev")),
            // `setup` is no exception any more: it used to be the one verb
            // spelled the other way round, which put two orders in one CLI.
            (vec!["terra", "dev", "setup"], Some("dev")),
            (vec!["terra", "setup"], None),
            // …and its box may be a recipe path, which is why it looked like it
            // needed a positional of its own.
            (
                vec!["terra", "./pi-dev.yaml", "setup"],
                Some("./pi-dev.yaml"),
            ),
        ] {
            let cli = Cli::parse_from(&argv);
            assert_eq!(cli.name.as_deref(), name, "{argv:?}");
            assert!(cli.cmd.is_some(), "{argv:?}");
            assert!(cli.validate().is_ok(), "{argv:?}");
        }
        // The verb-first spelling every other container tool uses is gone: the
        // box would be read as an argument of the verb, so it is an error and
        // not a box quietly addressed by the wrong name.
        for reversed in [
            &["stop", "dev"][..],
            &["logs", "dev"],
            &["show", "dev"],
            &["setup", "dev"],
            &["setup", "./pi-dev.yaml"],
        ] {
            let argv: Vec<&str> = std::iter::once("terra")
                .chain(reversed.iter().copied())
                .collect();
            assert!(Cli::try_parse_from(&argv).is_err(), "{argv:?}");
        }
    }

    /// …and that error is clap's "unexpected argument", which names neither the
    /// mistake nor the fix - so the reversal is named beside it. This is the
    /// spelling every other container tool takes, which makes it the first
    /// thing anyone types.
    ///
    /// The hint is offered only for verbs whose bare form cannot consume the
    /// box word as an argument.
    #[test]
    fn the_reversed_spelling_is_named_rather_than_left_to_clap() {
        let command = Cli::command();
        for sub in command.get_subcommands() {
            let word = sub.get_name();
            // A verb needing arguments cannot be parsed bare - and so can never
            // reach the hint at all; the loop below is what pins those.
            let Ok(Some(cmd)) = Cli::try_parse_from(["terra", word]).map(|c| c.cmd) else {
                continue;
            };
            if !cmd.takes_the_box() || sub.get_positionals().count() > 0 {
                continue;
            }
            assert!(Cli::try_parse_from(["terra", word, "dev"]).is_err());
            let hint = build_reversal_hint(&[word.to_string(), "dev".to_string()])
                .unwrap_or_else(|| panic!("`terra {word} dev` goes unexplained"));
            assert!(hint.contains(&format!("terra dev {word}")), "{hint}");
        }

        // …and a verb with a positional of its own is never guessed at: the
        // word could be something the verb wanted.
        for sub in command
            .get_subcommands()
            .filter(|s| s.get_positionals().count() > 0)
        {
            let typed = [sub.get_name().to_string(), "dev".to_string()];
            assert_eq!(build_reversal_hint(&typed), None, "{}", sub.get_name());
        }

        // A recipe path is a box argument too - and `terra setup ./ci.yaml` is
        // the spelling every doc carried before the box came first, so it is
        // the one people still have in their fingers and their CI scripts.
        let hint = build_reversal_hint(&["setup".to_string(), "./ci.yaml".to_string()])
            .expect("the old setup spelling goes unexplained");
        assert!(hint.contains("terra ./ci.yaml setup"), "{hint}");

        // Nothing else is guessed at.
        for quiet in [
            &["stop"][..],                   // no word to be the box
            &["exec", "dev"],                // the word could be its own argument
            &["stop", "not a box"],          // nothing a box could be called
            &["stop", "dev", "--wait", "5"], // the bare two-word form only
            &["nonsense", "dev"],
        ] {
            let typed: Vec<String> = quiet.iter().map(|w| (*w).to_string()).collect();
            assert_eq!(build_reversal_hint(&typed), None, "{quiet:?}");
        }
    }

    /// `--project` is one global flag rather than a copy per verb, so it can be
    /// written on either side of the verb and is read once.
    #[test]
    fn the_project_flag_is_global() {
        for argv in [
            vec!["terra", "--project", "/p", "dev", "stop"],
            vec!["terra", "dev", "stop", "--project", "/p"],
            vec!["terra", "--project", "/p"],
        ] {
            let cli = Cli::parse_from(&argv);
            assert_eq!(cli.project.as_deref(), Some(Path::new("/p")), "{argv:?}");
        }
    }

    /// The boot flags shape a boot, and a verb is not one. clap's
    /// `args_conflicts_with_subcommands` used to say so, but it also forbids the
    /// box a verb now needs, so [`Cli::validate`] says it instead. Without this the
    /// flag is silently dropped, which is the failure `cmd::start::plan` refuses on
    /// its own side once a box is already up.
    #[test]
    fn a_boot_flag_with_a_verb_is_refused_not_dropped() {
        for argv in [
            vec!["terra", "dev", "-d", "stop"],
            vec!["terra", "--root", "exec", "--", "ls"],
            vec!["terra", "dev", "--foreground", "logs"],
            vec!["terra", "--root", "ls"],
        ] {
            let cli = Cli::parse_from(&argv);
            let err = cli
                .validate()
                .expect_err("a boot flag was accepted alongside a verb")
                .to_string();
            assert!(err.contains("boot flags"), "{argv:?}: {err}");
            if argv.len() == 3 && argv[1] == "--root" && argv[2] == "ls" {
                assert!(err.contains("terra ls"), "{argv:?}: {err}");
                assert!(!err.contains("terra <box> ls"), "{argv:?}: {err}");
            }
        }
        // …and the bare form still takes every one of them.
        assert!(Cli::parse_from(["terra", "dev", "-d"]).validate().is_ok());
        assert!(
            Cli::parse_from(["terra", "dev", "--", "npm", "test"])
                .validate()
                .is_ok()
        );
    }

    /// `ls` is about the directory rather than one box, and it is the only verb
    /// that is: a box written before it would be read silently, so it is
    /// refused with the spelling that works. Every other verb takes the box,
    /// which is what makes the grammar one rule with one exception instead of
    /// two orders.
    #[test]
    fn ls_is_the_only_verb_that_takes_no_box() {
        let err = Cli::parse_from(["terra", "dev", "ls"])
            .validate()
            .expect_err("`ls` takes no box")
            .to_string();
        assert!(err.contains("terra ls"), "{err}");
        assert!(Cli::parse_from(["terra", "ls", "--all"]).validate().is_ok());

        // Both ways, off the verbs themselves: a new verb that quietly took no
        // box - or a second `ls` - fails here rather than reading a box name
        // nobody meant.
        for sub in Cli::command().get_subcommands() {
            let word = sub.get_name();
            let Ok(Some(cmd)) = Cli::try_parse_from(["terra", word]).map(|c| c.cmd) else {
                continue; // a verb with required arguments cannot be parsed bare
            };
            assert_eq!(
                cmd.takes_the_box(),
                word != "ls",
                "'{word}' disagrees with the one exception"
            );
        }
    }

    /// `terra <box>` puts box names and subcommands in one namespace, so
    /// terra's own words are reserved: a box named `logs` would be shadowed by
    /// the log viewer, silently for as long as nobody typed its name bare.
    /// [`name::RESERVED_NAMES`] and the real subcommand list are pinned to
    /// each other here, so a new subcommand fails this test until it is
    /// reserved too.
    #[test]
    fn every_terra_word_is_a_reserved_name_and_vice_versa() {
        let words: Vec<String> = Cli::command()
            .get_subcommands()
            .flat_map(|s| {
                std::iter::once(s.get_name().to_string())
                    .chain(s.get_all_aliases().map(String::from))
            })
            .chain(["help".to_string()])
            .collect();
        for word in &words {
            assert!(
                name::validate_box_name(word).is_err(),
                "'{word}' is a terra word and must not name a box"
            );
            assert!(
                name::RESERVED_NAMES.contains(&word.as_str()),
                "'{word}' is missing from RESERVED_NAMES"
            );
        }
        for reserved in name::RESERVED_NAMES {
            assert!(
                words.iter().any(|w| w == reserved),
                "'{reserved}' is reserved but is no longer a terra word"
            );
        }
    }

    /// Every "look here" line prints [`crate::state::BoxRef::logs_command`],
    /// and a hint is only worth printing if it is a command that runs - so the
    /// spelling is parsed back here rather than trusted. It used to be written
    /// out at each site as `terra logs <box>`, which is the verb-first spelling
    /// clap refuses: three messages prescribing a usage error, and a fourth
    /// naming no box at all, which resolves only in a directory that has one.
    #[test]
    fn the_hint_that_points_at_a_box_s_log_is_a_command_that_parses() {
        // A project path with no shell metacharacter in it, so splitting on
        // whitespace is the whole of the lexing this needs; that a path
        // carrying one comes back out of a real shell whole is
        // `render::tests::a_word_of_a_printed_command_survives_the_shell_it_is_pasted_into`.
        let bx = crate::state::BoxRef::from_state_dir(PathBuf::from("/p/dev"), Path::new("/p"));
        let hint = bx.build_logs_command();
        let argv: Vec<&str> = hint.split_whitespace().collect();

        let cli = Cli::try_parse_from(&argv)
            .unwrap_or_else(|e| panic!("`{hint}` is not a command terra takes: {e}"));
        assert_eq!(cli.name.as_deref(), Some("dev"), "{hint}");
        assert!(matches!(cli.cmd, Some(Cmd::Logs(_))), "{hint}");
        assert_eq!(cli.project.as_deref(), Some(Path::new("/p")), "{hint}");
        assert!(cli.validate().is_ok(), "{hint}");
    }

    /// Error-message verbs match clap in both directions: every spelling parses,
    /// and every clap subcommand has a spelling test.
    #[test]
    fn every_verb_is_worded_the_way_clap_spells_it() {
        // One parse per verb, typed as clap spells it - so argv's first word is
        // both what was typed and what `word` has to answer.
        let typed: &[&[&str]] = &[
            &["setup"],
            &["exec", "--", "ls"],
            &["put", "./a", "/b"],
            &["get", "/b", "./a"],
            &["stop"],
            &["storage", "show"],
            &["rm"],
            &["show"],
            &["ls"],
            &["logs"],
            &["sessions"],
            &["detach", "--all"],
        ];
        let mut worded: Vec<&str> = Vec::new();
        for argv in typed {
            let full: Vec<&str> = std::iter::once("terra")
                .chain(argv.iter().copied())
                .collect();
            let parsed = Cli::try_parse_from(&full)
                .unwrap_or_else(|e| panic!("`terra {}` no longer parses: {e}", argv.join(" ")));
            let Some(cmd) = parsed.cmd else {
                panic!("`terra {}` parses to no verb", argv.join(" "))
            };
            let word = cmd.verb();
            assert_eq!(word, argv[0], "`{}` is worded as '{word}'", argv.join(" "));
            worded.push(argv[0]);
        }
        for sub in Cli::command().get_subcommands() {
            assert!(
                worded.contains(&sub.get_name()),
                "'{}' is a terra verb that no case here words - a message built \
                 from its verb would go unchecked",
                sub.get_name()
            );
        }
    }

    /// The one exit code a script has to know about the bare form: a box that
    /// is already up, with no terminal to attach from and no `-d`, neither
    /// starts nor attaches. It was documented in the README only, which is not
    /// where somebody reading a CI failure looks.
    #[test]
    fn the_help_names_the_exit_code_for_a_box_that_is_already_running() {
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains(&crate::cmd::start::EXIT_VM_ALREADY_RUNNING.to_string()),
            "the bare form's exit code is not in `terra --help`:\n{help}"
        );
    }

    /// `--rebuild` rebuilds the filesystem; `--trust-recipe` accepts a recipe a
    /// guest could have written. One flag must never mean both.
    #[test]
    fn rebuilding_and_trusting_are_separate_flags() {
        let Some(Cmd::Setup(args)) =
            Cli::parse_from(["terra", "dev", "setup", "--trust-recipe"]).cmd
        else {
            panic!("expected setup")
        };
        assert!(args.trust_recipe && !args.rebuild);

        let Some(Cmd::Setup(args)) = Cli::parse_from(["terra", "dev", "setup", "--rebuild"]).cmd
        else {
            panic!("expected setup")
        };
        assert!(args.rebuild && !args.trust_recipe);
    }

    /// A detach is one client or every client - a bare `terra detach` with
    /// neither is a typo, and an id written with `--all` would be a cleanup
    /// nobody could predict.
    #[test]
    fn detach_takes_one_id_or_all() {
        assert!(Cli::try_parse_from(["terra", "dev", "detach", "3"]).is_ok());
        assert!(Cli::try_parse_from(["terra", "dev", "detach", "--all"]).is_ok());
        assert!(Cli::try_parse_from(["terra", "dev", "detach"]).is_err());
        assert!(Cli::try_parse_from(["terra", "dev", "detach", "3", "--all"]).is_err());
        let Some(Cmd::Detach(args)) = Cli::parse_from(["terra", "dev", "detach", "3"]).cmd else {
            panic!("expected detach")
        };
        assert_eq!(args.id, Some(3));
        assert!(!args.all);
    }

    /// The wait a stop uses is one number per role: the guest escalates to
    /// SIGKILL after [`DEFAULT_STOP_GRACE_SECS`], and the host
    /// waits that plus a teardown budget before killing the VM - taken from
    /// the flag whether or not the flag was given.
    #[test]
    fn the_stop_grace_has_one_default() {
        let Some(Cmd::Stop(stop_args)) = Cli::parse_from(["terra", "stop"]).cmd else {
            panic!("expected stop")
        };
        assert_eq!(
            stop_args.wait,
            DEFAULT_STOP_GRACE_SECS + STOP_TEARDOWN_ALLOWANCE_SECS
        );
        let Some(Cmd::Stop(stop_args)) = Cli::parse_from(["terra", "stop", "--wait", "5"]).cmd
        else {
            panic!("expected stop")
        };
        assert_eq!(stop_args.wait, 5);
        // A bare `--wait` used to mean "the default I would have used anyway".
        assert!(Cli::try_parse_from(["terra", "stop", "--wait"]).is_err());
        // Nothing waits for a stop `rm` never asked for.
        assert!(Cli::try_parse_from(["terra", "rm", "--wait", "5"]).is_err());
        assert!(Cli::try_parse_from(["terra", "rm", "--force", "--wait", "5"]).is_ok());
    }

    /// `terra setup` sets up; booting is `terra <box>`'s job. The boot flags
    /// used to ride on setup too, and which of the two commands you typed
    /// silently decided which sandbox `on_create` ran in.
    #[test]
    fn setup_takes_no_boot_flags() {
        for flag in ["-d", "--foreground", "--root"] {
            assert!(
                Cli::try_parse_from(["terra", "dev", "setup", flag]).is_err(),
                "`terra dev setup {flag}` should be refused"
            );
        }
    }

    /// `show` redacts `env:` values by default, so printing them is a thing you
    /// ask for by name rather than a thing you can get by mistake - its output
    /// is made to be redirected into a file or pasted into a bug report.
    #[test]
    fn showing_env_values_is_asked_for_and_not_the_default() {
        let show = |flags: &[&str]| -> ShowArgs {
            let typed: Vec<&str> = ["terra", "dev", "show"]
                .iter()
                .chain(flags)
                .copied()
                .collect();
            let Some(Cmd::Show(parsed)) = Cli::parse_from(typed).cmd else {
                panic!("expected show")
            };
            parsed
        };
        assert!(!show(&[]).with_env_values);
        assert!(show(&["--with-env-values"]).with_env_values);
    }

    /// Whether an exec'd command gets a PTY was read off terra's own stdin and
    /// nothing else, so neither side could be asked for: a script driving
    /// something that only works on a terminal had no way to say so, and one
    /// capturing output could not ask for the bytes a redirect would get.
    #[test]
    fn an_exec_takes_a_terminal_from_the_flags_before_its_own_stdin() {
        let exec = |flags: &[&str]| -> ExecArgs {
            let typed: Vec<&str> = ["terra", "dev", "exec"]
                .iter()
                .chain(flags)
                .chain(["--", "true"].iter())
                .copied()
                .collect();
            let Some(Cmd::Exec(parsed)) = Cli::parse_from(typed).cmd else {
                panic!("expected exec")
            };
            parsed
        };

        // Unasked, it is still whatever terra itself was started at.
        for is_at_a_terminal in [false, true] {
            assert_eq!(
                exec(&[]).wants_a_terminal(is_at_a_terminal),
                is_at_a_terminal
            );
        }
        // …and each flag wins over that, from either side.
        for asked in [&["--tty"][..], &["-t"]] {
            assert!(exec(asked).wants_a_terminal(false), "{asked:?}");
            assert!(exec(asked).wants_a_terminal(true), "{asked:?}");
        }
        for refused in [&["--no-tty"][..], &["-T"]] {
            assert!(!exec(refused).wants_a_terminal(true), "{refused:?}");
            assert!(!exec(refused).wants_a_terminal(false), "{refused:?}");
        }
        // Asking for both is refused rather than one of them quietly winning.
        assert!(Cli::try_parse_from(["terra", "dev", "exec", "-t", "-T", "--", "true"]).is_err());
    }

    /// The two commands that talk to the agent wait for it by default - both
    /// are used interactively, and a bound that cannot be turned off would cut
    /// off a shell somebody is typing into. `--agent-timeout` is how a script
    /// asks for one; the name says what it bounds, because a bare `--timeout`
    /// read as a bound on the command itself.
    #[test]
    fn waiting_for_the_agent_is_unbounded_until_a_timeout_is_asked_for() {
        let Some(Cmd::Exec(args)) = Cli::parse_from(["terra", "exec", "--", "true"]).cmd else {
            panic!("expected exec")
        };
        assert_eq!(args.agent.agent_timeout, None);
        let Some(Cmd::Put(args)) = Cli::parse_from(["terra", "put", "a", "/b"]).cmd else {
            panic!("expected put")
        };
        assert_eq!(args.agent.agent_timeout, None);

        let Some(Cmd::Exec(args)) =
            Cli::parse_from(["terra", "exec", "--agent-timeout", "5", "--", "true"]).cmd
        else {
            panic!("expected exec")
        };
        assert_eq!(args.agent.agent_timeout, Some(5));
        assert_eq!(
            Cli::parse_from(["terra", "--agent-timeout", "5"])
                .boot
                .agent
                .agent_timeout,
            Some(5)
        );
        let Some(Cmd::Get(args)) =
            Cli::parse_from(["terra", "get", "--agent-timeout", "5", "/b", "a"]).cmd
        else {
            panic!("expected get")
        };
        assert_eq!(args.agent.agent_timeout, Some(5));
    }

    #[test]
    fn logs_can_select_guest_diagnostics() {
        let Some(Cmd::Logs(args)) = Cli::parse_from(["terra", "logs", "--diagnostics"]).cmd else {
            panic!("expected logs")
        };
        assert!(args.diagnostics);
    }

    /// A copy is two paths and a direction: `put` sends the source in, `get`
    /// fetches it out, and the box is the ordinary one before the verb. There
    /// is no third positional and no mark on a path to tell the sides apart.
    #[test]
    fn put_and_get_take_two_paths_and_the_box_before_them() {
        let cli = Cli::parse_from(["terra", "dev", "put", "./a.txt", "/tmp/a"]);
        assert_eq!(cli.name.as_deref(), Some("dev"));
        let Some(Cmd::Put(args)) = cli.cmd else {
            panic!("expected put")
        };
        assert_eq!(
            (args.src.as_str(), args.dst.as_str()),
            ("./a.txt", "/tmp/a")
        );

        let Some(Cmd::Get(args)) = Cli::parse_from(["terra", "get", "/etc/x", "."]).cmd else {
            panic!("expected get")
        };
        assert_eq!((args.src.as_str(), args.dst.as_str()), ("/etc/x", "."));

        // Two paths exactly - a box smuggled in as a third is an error.
        assert!(Cli::try_parse_from(["terra", "put", "dev", "a", "/b"]).is_err());
        assert!(Cli::try_parse_from(["terra", "put", "a"]).is_err());
        // …and `cp` is gone rather than quietly meaning one of them.
        assert!(Cli::try_parse_from(["terra", "cp", "a", "/b"]).is_err());
    }

    /// One boot runs one way: `-d` and `--foreground` name two of them, so the
    /// pair is refused rather than one silently winning.
    #[test]
    fn detach_and_foreground_are_mutually_exclusive() {
        let fg = Cli::parse_from(["terra", "dev", "--foreground"]);
        assert!(fg.boot.foreground && !fg.boot.detach);
        assert!(Cli::try_parse_from(["terra", "dev", "-d", "--foreground"]).is_err());
    }

    #[test]
    fn exec_requires_a_command_after_the_separator() {
        let cli = Cli::parse_from([
            "terra", "dev", "exec", "--root", "--", "apk", "add", "strace",
        ]);
        assert_eq!(cli.name.as_deref(), Some("dev"));
        let Some(Cmd::Exec(args)) = cli.cmd else {
            panic!("expected exec")
        };
        assert!(args.root);
        assert_eq!(args.command, ["apk", "add", "strace"]);

        assert!(Cli::try_parse_from(["terra", "dev", "exec"]).is_err());
        assert!(Cli::try_parse_from(["terra", "exec"]).is_err());
    }
}
