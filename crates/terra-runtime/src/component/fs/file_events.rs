//! Native host notifications scoped to shared directories.

use std::path::{Component, Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::Poll;
use std::time::{Duration, Instant};

use super::host::terra::fs::host::{EventKind as FileEventKind, FileEvent};
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
pub(crate) const MAX_PENDING_FILE_EVENTS: usize = 4096;
const WATCH_START_TIMEOUT: Duration = Duration::from_secs(1);
pub(super) const MAX_NATIVE_WATCHES: usize = 1024;
use tokio::sync::mpsc;
use wasmtime::component::{Destination, StreamProducer, StreamResult};

use crate::component::fs::ShareGrant;

pub(super) struct FileEvents {
    receiver: mpsc::Receiver<QueuedEvent>,
    pending: Option<QueuedEvent>,
    _watcher: Option<WatchSession>,
}

struct QueuedEvent {
    event: FileEvent,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

struct Warnings(Option<Instant>);

impl Warnings {
    fn report(&mut self, message: impl std::fmt::Display) {
        if self
            .0
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(30))
        {
            log::warn!("shared file notifications degraded: {message}");
            self.0 = Some(Instant::now());
        }
    }
}

impl FileEvents {
    pub(super) async fn new(share: &ShareGrant) -> Self {
        let (sender, receiver) = mpsc::channel(MAX_PENDING_FILE_EVENTS);
        let watcher = WatchSession::start(share, sender).await;
        if watcher.is_none() {
            return Self::default();
        }
        Self {
            receiver,
            pending: None,
            _watcher: watcher,
        }
    }
}

impl Default for FileEvents {
    fn default() -> Self {
        Self {
            receiver: mpsc::channel(1).1,
            pending: None,
            _watcher: None,
        }
    }
}

struct WatchSession {
    sender: mpsc::Sender<Option<QueuedEvent>>,
    stopped: Arc<AtomicBool>,
}

impl Drop for WatchSession {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = self.sender.try_send(None);
    }
}

impl WatchSession {
    async fn start(share: &ShareGrant, output: mpsc::Sender<QueuedEvent>) -> Option<Self> {
        let (sender, receiver) = mpsc::channel(MAX_PENDING_FILE_EVENTS + 1);
        let stopped = Arc::new(AtomicBool::new(false));
        let session = Self {
            sender: sender.clone(),
            stopped: stopped.clone(),
        };
        let grant = share.clone();
        let (ready, initialized) = tokio::sync::oneshot::channel();
        let spawned = std::thread::Builder::new()
            .name("terra-file-watches".into())
            .spawn(move || {
                run_watches(&grant, stopped, sender, receiver, &output, ready);
            });
        match spawned {
            Ok(_) => match tokio::time::timeout(WATCH_START_TIMEOUT, initialized).await {
                Ok(Ok(())) => Some(session),
                Ok(Err(_)) => None,
                Err(_) => {
                    log::warn!("shared file notifications unavailable: watcher startup timed out");
                    None
                }
            },
            Err(error) => {
                log::warn!("shared file notifications unavailable: {error}");
                None
            }
        }
    }
}

struct DirectoryWatches {
    watcher: RecommendedWatcher,
    directories: std::collections::BTreeMap<PathBuf, tokio::sync::OwnedSemaphorePermit>,
    budget: Arc<tokio::sync::Semaphore>,
    stopped: Arc<AtomicBool>,
    warnings: Warnings,
}

impl DirectoryWatches {
    fn register_directory(&mut self, path: &Path) -> Option<std::fs::ReadDir> {
        if self.stopped.load(Ordering::Acquire) || self.directories.contains_key(path) {
            return None;
        }
        let Ok(permit) = self.budget.clone().try_acquire_owned() else {
            self.warnings
                .report("directory watch limit reached; new directories will not be watched");
            return None;
        };
        if !path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        {
            return None;
        }
        if let Err(error) = self.watcher.watch(path, RecursiveMode::NonRecursive) {
            self.warnings.report(error);
            return None;
        }
        self.directories.insert(path.to_owned(), permit);
        match std::fs::read_dir(path) {
            Ok(entries) => Some(entries),
            Err(error) => {
                self.warnings.report(error);
                None
            }
        }
    }

    fn register_tree(&mut self, path: &Path) {
        let mut directories = Vec::new();
        if let Some(entries) = self.register_directory(path) {
            directories.push(entries);
        }
        while !self.stopped.load(Ordering::Acquire) {
            let Some(entries) = directories.last_mut() else {
                break;
            };
            match entries.next() {
                Some(Ok(entry)) => {
                    if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                        if self.budget.available_permits() == 0 {
                            self.warnings.report("directory watch limit reached; remaining directories will not be watched");
                            break;
                        }
                        if let Some(children) = self.register_directory(&entry.path()) {
                            directories.push(children);
                        }
                    }
                }
                Some(Err(error)) => self.warnings.report(error),
                None => {
                    directories.pop();
                }
            }
        }
    }

    fn update(&mut self, root: &Path, event: &FileEvent) {
        let path = root.join(&event.path);
        if event.kind == FileEventKind::Remove {
            let removed = self
                .directories
                .keys()
                .filter(|known| known.starts_with(&path))
                .cloned()
                .collect::<Vec<_>>();
            for path in removed {
                let _ = self.watcher.unwatch(&path);
                self.directories.remove(&path);
            }
        } else if event.is_directory {
            self.register_tree(&path);
        }
    }
}

fn run_watches(
    grant: &ShareGrant,
    stopped: Arc<AtomicBool>,
    sender: mpsc::Sender<Option<QueuedEvent>>,
    mut receiver: mpsc::Receiver<Option<QueuedEvent>>,
    output: &mpsc::Sender<QueuedEvent>,
    ready: tokio::sync::oneshot::Sender<()>,
) {
    let root = &grant.root;
    let event_budget = grant.event_budget.clone();
    let callback_root = root.clone();
    let callback_stopped = stopped.clone();
    let mut warnings = Warnings(None);
    let callback = move |result| {
        if !callback_stopped.load(Ordering::Acquire) {
            forward_event(
                result,
                &callback_root,
                &sender,
                &event_budget,
                &mut warnings,
            );
        }
    };
    let watcher = match RecommendedWatcher::new(
        callback,
        notify::Config::default().with_follow_symlinks(false),
    ) {
        Ok(watcher) => watcher,
        Err(error) => {
            log::warn!("shared file notifications unavailable: {error}");
            return;
        }
    };
    let mut registry = DirectoryWatches {
        watcher,
        directories: std::collections::BTreeMap::new(),
        budget: grant.watch_budget.clone(),
        stopped,
        warnings: Warnings(None),
    };
    #[cfg(test)]
    if let Some(registration) = &grant.watch_registration {
        registration();
    }
    registry.register_tree(root);
    if ready.send(()).is_err() {
        return;
    }
    while let Some(Some(event)) = receiver.blocking_recv() {
        if registry.stopped.load(Ordering::Acquire) {
            break;
        }
        registry.update(root, &event.event);
        if output.try_send(event).is_err() {
            registry
                .warnings
                .report("event queue full or closed; dropping changes");
        }
    }
}

fn forward_event(
    result: notify::Result<Event>,
    root: &Path,
    sender: &mpsc::Sender<Option<QueuedEvent>>,
    budget: &std::sync::Arc<tokio::sync::Semaphore>,
    warnings: &mut Warnings,
) {
    let event = match result {
        Ok(event) => event,
        Err(error) => {
            warnings.report(error);
            return;
        }
    };
    if event.need_rescan() {
        warnings.report("native watcher dropped events; changes will not be replayed");
    }
    if matches!(event.kind, EventKind::Access(_)) {
        return;
    }
    for (index, path) in event.paths.iter().enumerate() {
        let Ok(permit) = budget.clone().try_acquire_owned() else {
            warnings.report("event queue full; dropping changes");
            continue;
        };
        let Ok(slot) = sender.try_reserve() else {
            warnings.report("event queue full; dropping changes");
            continue;
        };
        let Some(event) = normalize_path(root, &event, index, path) else {
            continue;
        };
        slot.send(Some(QueuedEvent {
            event,
            _permit: permit,
        }));
    }
}

fn is_valid_path(path: &str) -> bool {
    path.len() <= 4095
        && !path.contains('\0')
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn resolve_relative_event_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let mut parent = root.to_path_buf();
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return None;
        };
        if parent
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return None;
        }
        parts.push(name.to_str()?);
        parent.push(name);
    }
    Some(parts.join("/"))
}

#[cfg(test)]
fn normalize_event(root: &Path, event: &Event) -> Vec<FileEvent> {
    event
        .paths
        .iter()
        .enumerate()
        .filter_map(|(index, path)| normalize_path(root, event, index, path))
        .collect()
}

fn normalize_path(root: &Path, event: &Event, index: usize, path: &Path) -> Option<FileEvent> {
    if matches!(event.kind, EventKind::Access(_)) {
        return None;
    }
    let relative = resolve_relative_event_path(root, path)?;
    let kind = match event.kind {
        EventKind::Access(_) => return None,
        EventKind::Create(_) => FileEventKind::Create,
        EventKind::Remove(_) => FileEventKind::Remove,
        EventKind::Modify(ModifyKind::Metadata(_)) => FileEventKind::Metadata,
        EventKind::Modify(ModifyKind::Name(mode)) => match mode {
            RenameMode::From => FileEventKind::Remove,
            RenameMode::To => FileEventKind::Create,
            RenameMode::Both => {
                if index == 0 {
                    FileEventKind::Remove
                } else {
                    FileEventKind::Create
                }
            }
            RenameMode::Any | RenameMode::Other => {
                if path.symlink_metadata().is_ok() {
                    FileEventKind::Create
                } else {
                    FileEventKind::Remove
                }
            }
        },
        EventKind::Modify(ModifyKind::Any | ModifyKind::Data(_) | ModifyKind::Other) => {
            FileEventKind::Modify
        }
        EventKind::Any | EventKind::Other => {
            if path.symlink_metadata().is_ok() {
                FileEventKind::Modify
            } else {
                FileEventKind::Remove
            }
        }
    };
    let is_dir = matches!(
        event.kind,
        EventKind::Create(notify::event::CreateKind::Folder)
            | EventKind::Remove(notify::event::RemoveKind::Folder)
    ) || path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_dir());
    let event = FileEvent {
        path: relative,
        kind,
        is_directory: is_dir,
    };
    is_valid_path(&event.path).then_some(event)
}

impl<T: 'static> StreamProducer<T> for FileEvents {
    type Item = FileEvent;
    type Buffer = Option<FileEvent>;

    fn poll_produce<'a>(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        mut store: wasmtime::StoreContextMut<'a, T>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        if self.pending.is_none() {
            match self.receiver.poll_recv(context) {
                Poll::Ready(Some(frame)) => self.pending = Some(frame),
                Poll::Ready(None) => return Poll::Ready(Ok(StreamResult::Dropped)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if destination.remaining(&mut store) != Some(0) {
            destination.set_buffer(self.pending.take().map(|queued| queued.event));
        }
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory_registry(budget: Arc<tokio::sync::Semaphore>) -> DirectoryWatches {
        DirectoryWatches {
            watcher: RecommendedWatcher::new(
                |_| {},
                notify::Config::default().with_follow_symlinks(false),
            )
            .unwrap(),
            directories: std::collections::BTreeMap::new(),
            budget,
            stopped: Arc::new(AtomicBool::new(false)),
            warnings: Warnings(None),
        }
    }

    #[test]
    fn directory_registration_is_bounded_across_shares_and_releases_removed_trees() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(first.path().join("nested/deeper")).unwrap();
        let budget = Arc::new(tokio::sync::Semaphore::new(2));
        let mut first_registry = directory_registry(budget.clone());
        let mut second_registry = directory_registry(budget.clone());
        first_registry.register_tree(first.path());
        second_registry.register_tree(second.path());
        assert_eq!(first_registry.directories.len(), 2);
        assert!(second_registry.directories.is_empty());
        assert_eq!(budget.available_permits(), 0);
        first_registry.update(
            first.path(),
            &FileEvent {
                path: "nested".into(),
                kind: FileEventKind::Remove,
                is_directory: true,
            },
        );
        assert_eq!(budget.available_permits(), 1);
        second_registry.register_tree(second.path());
        assert_eq!(second_registry.directories.len(), 1);
        drop(first_registry);
        drop(second_registry);
        assert_eq!(budget.available_permits(), 2);
    }

    #[tokio::test]
    async fn watches_new_directories_and_releases_resources_on_cancellation() {
        let root = tempfile::tempdir().unwrap();
        let grant = ShareGrant::new(&root.path().canonicalize().unwrap(), false).unwrap();
        let mut events = FileEvents::new(&grant).await;
        std::fs::create_dir(root.path().join("nested")).unwrap();
        receive_path(&mut events, "nested").await;
        std::fs::write(root.path().join("nested/file"), "contents").unwrap();
        receive_path(&mut events, "nested/file").await;
        let start = Instant::now();
        drop(events);
        assert!(start.elapsed() < Duration::from_secs(1));
        tokio::time::timeout(Duration::from_secs(5), async {
            let _all = grant
                .watch_budget
                .acquire_many(u32::try_from(MAX_NATIVE_WATCHES).unwrap())
                .await
                .unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn access_events_do_not_consume_capacity_or_report_overflow() {
        let root = tempfile::tempdir().unwrap();
        let budget = Arc::new(tokio::sync::Semaphore::new(0));
        let (sender, mut receiver) = mpsc::channel(1);
        let mut warnings = Warnings(None);
        forward_event(
            Ok(
                Event::new(EventKind::Access(notify::event::AccessKind::Any))
                    .add_path(root.path().join("file")),
            ),
            root.path(),
            &sender,
            &budget,
            &mut warnings,
        );
        assert!(warnings.0.is_none());
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn normalizes_renames_and_rejects_access_and_outside_paths() {
        let root = tempfile::tempdir().unwrap();
        let rename = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path(root.path().join("old"))
            .add_path(root.path().join("new"));
        let events = normalize_event(root.path(), &rename);
        assert_eq!(
            events
                .iter()
                .map(|event| (event.path.as_str(), event.kind))
                .collect::<Vec<_>>(),
            [
                ("old", FileEventKind::Remove),
                ("new", FileEventKind::Create)
            ]
        );
        let access = Event::new(EventKind::Access(notify::event::AccessKind::Any))
            .add_path(root.path().join("new"));
        assert!(normalize_event(root.path(), &access).is_empty());
        let outside = Event::new(EventKind::Any).add_path(root.path().join("../outside"));
        assert!(normalize_event(root.path(), &outside).is_empty());
    }

    #[test]
    fn normalizes_content_metadata_creation_and_removal() {
        let root = tempfile::tempdir().unwrap();
        for (native, expected) in [
            (
                EventKind::Create(notify::event::CreateKind::File),
                FileEventKind::Create,
            ),
            (
                EventKind::Remove(notify::event::RemoveKind::File),
                FileEventKind::Remove,
            ),
            (
                EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Size)),
                FileEventKind::Modify,
            ),
            (
                EventKind::Modify(ModifyKind::Metadata(
                    notify::event::MetadataKind::Permissions,
                )),
                FileEventKind::Metadata,
            ),
        ] {
            let events = normalize_event(
                root.path(),
                &Event::new(native).add_path(root.path().join("file")),
            );
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].kind, expected);
        }
        for path in ["", "/absolute", "../outside", "nested/../outside", "a\0b"] {
            assert!(!is_valid_path(path));
        }
        assert!(!is_valid_path(&"x".repeat(4096)));
    }

    #[cfg(unix)]
    #[test]
    fn does_not_forward_through_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        let mut registry = directory_registry(Arc::new(tokio::sync::Semaphore::new(4)));
        registry.register_tree(root.path());
        assert_eq!(registry.directories.len(), 1);
        assert!(registry.directories.contains_key(root.path()));
        let event = Event::new(EventKind::Any).add_path(root.path().join("link/file"));
        assert!(normalize_event(root.path(), &event).is_empty());
    }

    #[tokio::test]
    async fn native_watcher_delivers_host_writes_and_atomic_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let grant = ShareGrant::new(&root, true).unwrap();
        let mut events = FileEvents::new(&grant).await;
        std::fs::write(root.join("source"), "first").unwrap();
        receive_path(&mut events, "source").await;
        std::fs::write(root.join("replacement"), "second").unwrap();
        std::fs::rename(root.join("replacement"), root.join("source")).unwrap();
        receive_path(&mut events, "source").await;
        assert_eq!(
            std::fs::read_to_string(root.join("source")).unwrap(),
            "second"
        );
    }

    #[tokio::test]
    async fn cancelling_registration_releases_the_watcher_after_the_host_call_returns() {
        let root = tempfile::tempdir().unwrap();
        let mut grant = ShareGrant::new(&root.path().canonicalize().unwrap(), true).unwrap();
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let blocked = std::sync::Mutex::new(blocked);
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let registration_entered = entered.clone();
        grant.watch_registration = Some(Arc::new(move || {
            registration_entered.add_permits(1);
            let _ = blocked.lock().unwrap().recv_timeout(Duration::from_secs(5));
        }));
        let (sender, mut receiver) = mpsc::channel(1);
        let mut startup = Box::pin(WatchSession::start(&grant, sender));
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                _ = &mut startup => panic!("watcher became ready while registration was blocked"),
                permit = entered.acquire() => permit.unwrap().forget(),
            }
        })
        .await
        .unwrap();
        drop(startup);
        drop(release);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), receiver.recv())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(grant.watch_budget.available_permits(), MAX_NATIVE_WATCHES);
    }

    async fn receive_path(events: &mut FileEvents, path: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = events.receiver.recv().await.unwrap();
                if event.event.path == path {
                    return;
                }
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn shares_compete_for_one_bounded_event_budget() {
        let root = tempfile::tempdir().unwrap();
        let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let (first_sender, mut first) = mpsc::channel(4);
        let (second_sender, mut second) = mpsc::channel(4);
        let mut warnings = Warnings(None);
        let event =
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path(root.path().join("file"));
        forward_event(
            Ok(event.clone()),
            root.path(),
            &first_sender,
            &budget,
            &mut warnings,
        );
        forward_event(
            Ok(event.clone()),
            root.path(),
            &second_sender,
            &budget,
            &mut warnings,
        );
        assert!(second.try_recv().is_err());
        drop(first.try_recv().unwrap().unwrap());
        forward_event(
            Ok(event),
            root.path(),
            &second_sender,
            &budget,
            &mut warnings,
        );
        assert_eq!(second.try_recv().unwrap().unwrap().event.path, "file");
    }

    #[test]
    fn forwarding_recovers_after_overflow_and_native_errors() {
        let root = tempfile::tempdir().unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        let mut warnings = Warnings(None);
        let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(4096));
        let event =
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path(root.path().join("file"));
        forward_event(
            Ok(event.clone()),
            root.path(),
            &sender,
            &budget,
            &mut warnings,
        );
        forward_event(
            Ok(event.clone()),
            root.path(),
            &sender,
            &budget,
            &mut warnings,
        );
        assert!(warnings.0.is_some());
        let first = receiver.try_recv().unwrap().unwrap();
        assert!(receiver.try_recv().is_err());
        forward_event(
            Err(notify::Error::generic("backend failure")),
            root.path(),
            &sender,
            &budget,
            &mut warnings,
        );
        forward_event(Ok(event), root.path(), &sender, &budget, &mut warnings);
        assert_eq!(
            receiver.try_recv().unwrap().unwrap().event.path,
            first.event.path
        );
    }
}
