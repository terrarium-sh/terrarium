use std::collections::{BTreeMap, VecDeque};
use std::task::{Context, Poll};

use futures::{FutureExt, StreamExt, future::LocalBoxFuture, stream::FuturesUnordered};

use super::PendingReply;

const MAX_ACTIVE_IO: usize = 32;
const MAX_PENDING_IO: usize = super::QUEUE_SIZE as usize;

pub(super) struct PreparedIo {
    pub identity: (u64, u64),
    pub work: LocalBoxFuture<'static, Result<Vec<u8>, i32>>,
}

pub(super) struct CompletedIo {
    identity: (u64, u64),
    pub reply: PendingReply,
    pub result: Result<Vec<u8>, i32>,
}

#[derive(Default)]
pub(super) struct IoScheduler {
    pending: VecDeque<(PreparedIo, PendingReply)>,
    active: FuturesUnordered<LocalBoxFuture<'static, CompletedIo>>,
    active_files: BTreeMap<(u64, u64), u64>,
}

impl IoScheduler {
    pub fn discard_pending(&mut self) {
        self.pending.clear();
    }

    pub fn contains_generation(&self, generation: u64) -> bool {
        self.active_files
            .values()
            .any(|active| *active == generation)
            || self
                .pending
                .iter()
                .any(|(_, reply)| reply.generation == generation)
    }

    pub fn enqueue(&mut self, operation: PreparedIo, reply: PendingReply) -> Result<(), i32> {
        if self.pending.len() + self.active.len() == MAX_PENDING_IO {
            return Err(16);
        }
        self.pending.push_back((operation, reply));
        Ok(())
    }

    pub fn poll_complete(&mut self, context: &mut Context<'_>) -> Option<CompletedIo> {
        while self.active.len() < MAX_ACTIVE_IO {
            let Some(index) = self
                .pending
                .iter()
                .position(|(operation, _)| !self.active_files.contains_key(&operation.identity))
            else {
                break;
            };
            let Some((operation, reply)) = self.pending.remove(index) else {
                break;
            };
            self.active_files
                .insert(operation.identity, reply.generation);
            self.active.push(
                async move {
                    CompletedIo {
                        identity: operation.identity,
                        reply,
                        result: operation.work.await,
                    }
                }
                .boxed_local(),
            );
        }
        if let Poll::Ready(Some(completed)) = self.active.poll_next_unpin(context) {
            self.active_files.remove(&completed.identity);
            Some(completed)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{channel::oneshot, task::noop_waker};

    fn reply(unique: u64) -> PendingReply {
        PendingReply {
            queue: 1,
            head: 0,
            output: Vec::new(),
            unique,
            generation: 1,
        }
    }

    #[test]
    fn stalled_io_preserves_file_order_across_reset_without_blocking_other_files() {
        let (release, stalled) = oneshot::channel();
        let mut io = IoScheduler::default();
        io.enqueue(
            PreparedIo {
                identity: (0, 1),
                work: async move { stalled.await.map_err(|_| 5) }.boxed_local(),
            },
            reply(1),
        )
        .unwrap();
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(io.poll_complete(&mut context).is_none());
        io.discard_pending();
        let mut after_reset = reply(2);
        after_reset.generation = 2;
        io.enqueue(
            PreparedIo {
                identity: (0, 1),
                work: async { Ok(vec![2]) }.boxed_local(),
            },
            after_reset,
        )
        .unwrap();
        io.enqueue(
            PreparedIo {
                identity: (0, 2),
                work: async { Ok(vec![3]) }.boxed_local(),
            },
            reply(3),
        )
        .unwrap();
        let completed = io.poll_complete(&mut context).unwrap();
        assert_eq!(completed.reply.unique, 3);
        assert!(io.poll_complete(&mut context).is_none());
        release.send(vec![1]).unwrap();
        assert_eq!(io.poll_complete(&mut context).unwrap().reply.unique, 1);
        assert_eq!(io.poll_complete(&mut context).unwrap().reply.unique, 2);
    }

    #[test]
    fn io_admission_and_execution_are_bounded_and_drop_cancels_reads() {
        let mut releases = Vec::new();
        let mut io = IoScheduler::default();
        for node in 0..MAX_PENDING_IO {
            let (release, stalled) = oneshot::channel();
            releases.push(release);
            io.enqueue(
                PreparedIo {
                    identity: (0, node as u64),
                    work: async move { stalled.await.map_err(|_| 5) }.boxed_local(),
                },
                reply(node as u64),
            )
            .unwrap();
        }
        assert_eq!(
            io.enqueue(
                PreparedIo {
                    identity: (0, u64::MAX),
                    work: async { Ok(Vec::new()) }.boxed_local(),
                },
                reply(u64::MAX)
            ),
            Err(16)
        );
        let waker = noop_waker();
        assert!(io.poll_complete(&mut Context::from_waker(&waker)).is_none());
        assert_eq!(io.active.len(), MAX_ACTIVE_IO);
        assert_eq!(io.pending.len(), MAX_PENDING_IO - MAX_ACTIVE_IO);
        io.discard_pending();
        assert_eq!(io.active.len(), MAX_ACTIVE_IO);
        assert!(io.pending.is_empty());
        assert!(
            releases[..MAX_ACTIVE_IO]
                .iter()
                .all(|release| !release.is_canceled())
        );
        assert!(
            releases[MAX_ACTIVE_IO..]
                .iter()
                .all(oneshot::Sender::is_canceled)
        );
        assert!(io.contains_generation(1));
        assert!(!io.contains_generation(2));
        drop(io);
        assert!(releases.iter().all(oneshot::Sender::is_canceled));
    }
}
