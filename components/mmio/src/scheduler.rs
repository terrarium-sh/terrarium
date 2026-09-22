use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use crate::bindings::exports::terra::mmio::router::Error;

const DATA_LIMIT: usize = 64;
const CONTROL_LIMIT: usize = 64;
const CONTROL_BURST: usize = 8;
const TICKET_LIMIT: usize = DATA_LIMIT + CONTROL_LIMIT + terra_limits::MAX_VCPUS as usize;

#[derive(Clone, Copy, PartialEq)]
pub enum Class {
    Data,
    Control,
}

struct Ticket {
    id: u64,
    class: Class,
    granted: bool,
    waker: Waker,
}
#[derive(Default)]
struct Scheduler {
    tickets: VecDeque<Ticket>,
    next_id: u64,
    data: usize,
    controls: usize,
    control_burst: usize,
}
static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler {
    tickets: VecDeque::new(),
    next_id: 0,
    data: 0,
    controls: 0,
    control_burst: 0,
});

impl Scheduler {
    fn enqueue(&mut self, class: Class, waker: Waker) -> Result<u64, Error> {
        if self.tickets.iter().filter(|ticket| !ticket.granted).count() + self.data + self.controls
            >= TICKET_LIMIT
        {
            return Err(Error::Busy);
        }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(Error::Busy)?;
        self.tickets.push_back(Ticket {
            id,
            class,
            granted: false,
            waker,
        });
        self.schedule();
        Ok(id)
    }
    fn schedule(&mut self) {
        loop {
            let data = (self.data + self.controls < DATA_LIMIT)
                .then(|| {
                    self.tickets
                        .iter()
                        .position(|ticket| !ticket.granted && ticket.class == Class::Data)
                })
                .flatten();
            let control = (self.controls < CONTROL_LIMIT)
                .then(|| {
                    self.tickets
                        .iter()
                        .position(|ticket| !ticket.granted && ticket.class == Class::Control)
                })
                .flatten();
            let Some(index) = (self.control_burst < CONTROL_BURST)
                .then(|| control.or(data))
                .flatten()
                .or_else(|| data.or(control))
            else {
                break;
            };
            let ticket = &mut self.tickets[index];
            ticket.granted = true;
            match ticket.class {
                Class::Data => {
                    self.data += 1;
                    self.control_burst = 0;
                }
                Class::Control => {
                    self.controls += 1;
                    self.control_burst = (self.control_burst + 1).min(CONTROL_BURST);
                }
            }
            ticket.waker.wake_by_ref();
        }
    }
    fn release(&mut self, class: Class) {
        match class {
            Class::Data => self.data -= 1,
            Class::Control => self.controls -= 1,
        }
        self.schedule();
    }
    fn cancel(&mut self, id: u64) {
        let Some(index) = self.tickets.iter().position(|ticket| ticket.id == id) else {
            return;
        };
        let Some(ticket) = self.tickets.remove(index) else {
            return;
        };
        if ticket.granted {
            self.release(ticket.class);
        }
    }
}

pub struct Acquire {
    class: Class,
    id: Option<u64>,
}
pub fn acquire(class: Class) -> Acquire {
    Acquire { class, id: None }
}
pub struct Permit(Class);
impl Future for Acquire {
    type Output = Result<Permit, Error>;
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut scheduler = SCHEDULER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = if let Some(id) = self.id {
            id
        } else {
            let id = scheduler.enqueue(self.class, context.waker().clone())?;
            self.id = Some(id);
            id
        };
        let Some(index) = scheduler.tickets.iter().position(|ticket| ticket.id == id) else {
            self.id = None;
            return Poll::Ready(Err(Error::Busy));
        };
        if scheduler.tickets[index].granted {
            scheduler.tickets.remove(index);
            self.id = None;
            Poll::Ready(Ok(Permit(self.class)))
        } else {
            scheduler.tickets[index].waker.clone_from(context.waker());
            Poll::Pending
        }
    }
}
impl Drop for Acquire {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            SCHEDULER
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .cancel(id);
        }
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        SCHEDULER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release(self.0);
    }
}
