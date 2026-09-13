use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use super::Error;

const DATA_LIMIT: usize = 64;
const CONTROL_LIMIT: usize = 64;
const CONTROL_BURST: usize = 8;
const TICKET_LIMIT: usize = DATA_LIMIT + CONTROL_LIMIT + super::MAX_VCPUS;

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
            let next = if self.control_burst < CONTROL_BURST {
                control.or(data)
            } else {
                data.or(control)
            };
            let Some(index) = next else { break };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn enqueue(scheduler: &mut Scheduler, class: Class) -> u64 {
        scheduler.enqueue(class, Waker::noop().clone()).unwrap()
    }

    #[test]
    fn control_capacity_survives_data_saturation_and_cancellation_releases_grants() {
        let mut scheduler = Scheduler::default();
        let data = (0..DATA_LIMIT)
            .map(|_| enqueue(&mut scheduler, Class::Data))
            .collect::<Vec<_>>();
        let waiting = enqueue(&mut scheduler, Class::Data);
        let control = enqueue(&mut scheduler, Class::Control);
        assert_eq!((scheduler.data, scheduler.controls), (DATA_LIMIT, 1));
        scheduler.cancel(control);
        scheduler.cancel(data[0]);
        assert!(
            scheduler
                .tickets
                .iter()
                .find(|ticket| ticket.id == waiting)
                .unwrap()
                .granted
        );
        for id in data.into_iter().skip(1).chain([waiting]) {
            scheduler.cancel(id);
        }
        assert_eq!((scheduler.data, scheduler.controls), (0, 0));
        assert!(scheduler.tickets.is_empty());
    }

    #[test]
    fn async_permits_bound_waiters_and_release_cancelled_reservations() {
        let mut context = Context::from_waker(Waker::noop());
        let mut permits = Vec::new();
        for class in std::iter::repeat_n(Class::Data, DATA_LIMIT)
            .chain(std::iter::repeat_n(Class::Control, CONTROL_LIMIT))
        {
            let Poll::Ready(Ok(permit)) = Pin::new(&mut acquire(class)).poll(&mut context) else {
                panic!("available permit");
            };
            permits.push(permit);
        }
        let mut waiting = (0..super::super::MAX_VCPUS)
            .map(|_| acquire(Class::Data))
            .collect::<Vec<_>>();
        for request in &mut waiting {
            assert!(Pin::new(request).poll(&mut context).is_pending());
        }
        assert!(matches!(
            Pin::new(&mut acquire(Class::Data)).poll(&mut context),
            Poll::Ready(Err(Error::Busy))
        ));
        drop(permits);
        drop(waiting);
        let scheduler = SCHEDULER.lock().unwrap();
        assert_eq!((scheduler.data, scheduler.controls), (0, 0));
        assert!(scheduler.tickets.is_empty());
    }

    #[test]
    fn a_control_burst_yields_to_waiting_data() {
        let mut scheduler = Scheduler {
            data: DATA_LIMIT,
            controls: CONTROL_LIMIT,
            ..Scheduler::default()
        };
        let data = enqueue(&mut scheduler, Class::Data);
        let control = enqueue(&mut scheduler, Class::Control);
        scheduler.data = 0;
        scheduler.controls = 0;
        scheduler.control_burst = CONTROL_BURST;
        scheduler.schedule();
        assert!(scheduler.tickets.iter().all(|ticket| ticket.granted));
        assert_eq!(scheduler.control_burst, 1);
        scheduler.cancel(data);
        scheduler.cancel(control);
    }
}
