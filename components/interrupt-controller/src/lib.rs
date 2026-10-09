//! Emulates the x86 interrupt controller without host authority.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "interrupt-controller", path: "wit", generate_all, additional_derives: [PartialEq, Eq] });
}

use bindings::exports::terra::interrupt_controller::controller::{
    Config, Error, Guest, IoapicReply, IrqLevel, Mode, X86Interrupt,
};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

const PINS: usize = terra_limits::X86_IOAPIC_PINS as usize;
const REGISTER_SELECT: u8 = 0;
const WINDOW: u8 = 0x10;
const VERSION_REGISTER: u8 = 1;
const VERSION: u32 = ((terra_limits::X86_IOAPIC_PINS - 1) << 16) | 0x11;
const REDIRECTION_BASE: u8 = 0x10;
const MASKED: u32 = 1 << 16;
const LEVEL_TRIGGERED: u32 = 1 << 15;

struct Controller {
    mode: Mode,
    routes: Vec<u8>,
    levels: Vec<bool>,
    register: u8,
    /// Low and high register halves of each redirection entry.
    redirection: [[u32; 2]; PINS],
    asserted: [bool; PINS],
}

impl Controller {
    fn new(config: Config) -> Result<Self, Error> {
        if config.routes.len() > terra_limits::MAX_DEVICES {
            return Err(Error::InvalidSlot);
        }
        let routes = config
            .routes
            .into_iter()
            .map(|route| {
                u8::try_from(route)
                    .ok()
                    .filter(|route| usize::from(*route) < PINS)
                    .ok_or(Error::InvalidSlot)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            mode: config.mode,
            levels: vec![false; routes.len()],
            routes,
            register: 0,
            redirection: [[MASKED, 0]; PINS],
            asserted: [false; PINS],
        })
    }

    fn access(&mut self, offset: u8, width: u8, write: bool, value: u32) -> IoapicReply {
        let mut reply = IoapicReply {
            value: 0,
            interrupts: Vec::new(),
        };
        match (offset, width, write) {
            (REGISTER_SELECT, 4, false) => reply.value = u32::from(self.register),
            (REGISTER_SELECT, 4, true) => self.register = value.to_le_bytes()[0],
            (WINDOW, 4, false) => reply.value = self.read_register(),
            (WINDOW, 4, true) => reply.interrupts.extend(
                self.write_register(value)
                    .filter(|pin| self.asserted[*pin])
                    .and_then(|pin| self.deliver(pin)),
            ),
            _ => {}
        }
        reply
    }

    /// Returns the GSI whose aggregate level changed.
    fn line(&mut self, slot: u8, level: bool) -> Result<Option<u8>, Error> {
        let slot = usize::from(slot);
        let gsi = *self.routes.get(slot).ok_or(Error::InvalidSlot)?;
        self.levels[slot] = level;
        let aggregated = self
            .routes
            .iter()
            .zip(&self.levels)
            .any(|(route, level)| *route == gsi && *level);
        let asserted = &mut self.asserted[usize::from(gsi)];
        if *asserted == aggregated {
            return Ok(None);
        }
        *asserted = aggregated;
        Ok(Some(gsi))
    }

    fn ioapic_line(&mut self, slot: u8, level: bool) -> Result<Option<X86Interrupt>, Error> {
        Ok(self
            .line(slot, level)?
            .map(usize::from)
            .filter(|pin| self.asserted[*pin])
            .and_then(|pin| self.deliver(pin)))
    }

    fn eoi(&self, vector: u8) -> Vec<X86Interrupt> {
        (0..PINS)
            .filter(|pin| self.asserted[*pin])
            .filter_map(|pin| self.deliver(pin))
            .filter(|interrupt| interrupt.level_triggered && interrupt.vector == vector)
            .collect()
    }

    fn redirection_half(&self) -> Option<(usize, usize)> {
        let index = usize::from(self.register.checked_sub(REDIRECTION_BASE)?);
        (index / 2 < PINS).then_some((index / 2, index % 2))
    }

    fn read_register(&self) -> u32 {
        if self.register == VERSION_REGISTER {
            return VERSION;
        }
        self.redirection_half()
            .map_or(0, |(pin, half)| self.redirection[pin][half])
    }

    /// Returns the pin whose redirection entry was written.
    fn write_register(&mut self, value: u32) -> Option<usize> {
        let (pin, half) = self.redirection_half()?;
        self.redirection[pin][half] = value;
        Some(pin)
    }

    fn deliver(&self, pin: usize) -> Option<X86Interrupt> {
        let [low, high] = self.redirection[pin];
        (low & MASKED == 0).then_some(X86Interrupt {
            vector: low.to_le_bytes()[0],
            destination: high.to_le_bytes()[3],
            level_triggered: low & LEVEL_TRIGGERED != 0,
        })
    }
}

static CONTROLLER: LazyLock<Mutex<Option<Controller>>> = LazyLock::new(|| Mutex::new(None));

fn controller() -> MutexGuard<'static, Option<Controller>> {
    CONTROLLER.lock().unwrap_or_else(PoisonError::into_inner)
}

fn with_controller<T>(
    mode: Mode,
    operate: impl FnOnce(&mut Controller) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut state = controller();
    let controller = state
        .as_mut()
        .filter(|controller| controller.mode == mode)
        .ok_or(Error::InvalidState)?;
    operate(controller)
}

struct Component;

#[allow(unsafe_code)]
mod component_exports {
    use super::{Component, bindings};
    bindings::export!(Component with_types_in bindings);
}

impl Guest for Component {
    fn configure(config: Config) -> Result<(), Error> {
        let mut controller = controller();
        if controller.is_some() {
            return Err(Error::InvalidState);
        }
        *controller = Some(Controller::new(config)?);
        Ok(())
    }

    fn irq_line(slot: u8, asserted: bool) -> Result<Option<IrqLevel>, Error> {
        with_controller(Mode::IrqLines, |controller| {
            Ok(controller.line(slot, asserted)?.map(|gsi| IrqLevel {
                gsi: u32::from(gsi),
                asserted: controller.asserted[usize::from(gsi)],
            }))
        })
    }

    fn ioapic_line(slot: u8, asserted: bool) -> Result<Vec<X86Interrupt>, Error> {
        with_controller(Mode::Ioapic, |controller| {
            Ok(controller
                .ioapic_line(slot, asserted)?
                .into_iter()
                .collect())
        })
    }

    fn access(offset: u8, width: u8, write: bool, value: u32) -> Result<IoapicReply, Error> {
        with_controller(Mode::Ioapic, |controller| {
            Ok(controller.access(offset, width, write, value))
        })
    }

    fn eoi(vector: u8) -> Result<Vec<X86Interrupt>, Error> {
        with_controller(Mode::Ioapic, |controller| Ok(controller.eoi(vector)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller(mode: Mode, routes: Vec<u32>) -> Controller {
        Controller::new(Config { mode, routes }).unwrap()
    }

    fn access(controller: &mut Controller, offset: u8, write: bool, value: u32) -> IoapicReply {
        controller.access(offset, 4, write, value)
    }

    fn redirection(controller: &mut Controller, pin: u8, low: u32, high: u32) {
        access(
            controller,
            REGISTER_SELECT,
            true,
            u32::from(REDIRECTION_BASE + pin * 2),
        );
        access(controller, WINDOW, true, low);
        access(
            controller,
            REGISTER_SELECT,
            true,
            u32::from(REDIRECTION_BASE + pin * 2 + 1),
        );
        access(controller, WINDOW, true, high);
    }

    #[test]
    fn shared_routes_only_transition_with_the_aggregate_level() {
        let mut controller = controller(Mode::Ioapic, vec![5, 5]);
        redirection(&mut controller, 5, 0x31, 2 << 24);
        assert_eq!(
            controller.ioapic_line(0, true).unwrap(),
            Some(X86Interrupt {
                vector: 0x31,
                destination: 2,
                level_triggered: false,
            })
        );
        assert_eq!(controller.ioapic_line(1, true).unwrap(), None);
        assert_eq!(controller.line(0, false).unwrap(), None);
        assert_eq!(controller.line(1, false).unwrap(), Some(5));
        assert!(!controller.asserted[5]);
    }

    #[test]
    fn version_register_advertises_the_available_pins() {
        let mut controller = controller(Mode::Ioapic, vec![]);
        access(&mut controller, REGISTER_SELECT, true, 1);
        let version = access(&mut controller, WINDOW, false, 0).value;
        assert_eq!(((version >> 16) & 0xff) + 1, u32::try_from(PINS).unwrap());
        assert_eq!(version & 0xff, 0x11);
    }

    #[test]
    fn redirection_entries_start_masked_and_keep_both_halves() {
        let mut controller = controller(Mode::Ioapic, vec![]);
        access(
            &mut controller,
            REGISTER_SELECT,
            true,
            u32::from(REDIRECTION_BASE),
        );
        assert_eq!(access(&mut controller, WINDOW, false, 0).value, 1 << 16);
        access(&mut controller, WINDOW, true, 0x31);
        access(
            &mut controller,
            REGISTER_SELECT,
            true,
            u32::from(REDIRECTION_BASE + 1),
        );
        access(&mut controller, WINDOW, true, 2);
        access(
            &mut controller,
            REGISTER_SELECT,
            true,
            u32::from(REDIRECTION_BASE),
        );
        assert_eq!(access(&mut controller, WINDOW, false, 0).value, 0x31);
        access(
            &mut controller,
            REGISTER_SELECT,
            true,
            u32::from(REDIRECTION_BASE + 1),
        );
        assert_eq!(access(&mut controller, WINDOW, false, 0).value, 2);
    }

    #[test]
    fn eoi_redelivers_an_asserted_level_interrupt() {
        let mut controller = controller(Mode::Ioapic, vec![5]);
        redirection(&mut controller, 5, 0x31 | LEVEL_TRIGGERED, 0);
        let delivered = controller.ioapic_line(0, true).unwrap();
        assert!(delivered.is_some());
        assert_eq!(controller.eoi(0x31), Vec::from_iter(delivered));
        assert_eq!(controller.eoi(0x32), []);
    }

    #[test]
    fn writing_an_asserted_redirection_entry_redelivers_it() {
        let mut controller = controller(Mode::Ioapic, vec![5]);
        redirection(&mut controller, 5, 0x31, 0);
        assert!(controller.ioapic_line(0, true).unwrap().is_some());
        access(
            &mut controller,
            REGISTER_SELECT,
            true,
            u32::from(REDIRECTION_BASE + 5 * 2),
        );
        assert_eq!(
            access(&mut controller, WINDOW, true, 0x32).interrupts[0].vector,
            0x32
        );
    }

    #[test]
    fn accepts_every_device_slot_and_rejects_invalid_configuration() {
        let mut controller = controller(Mode::Ioapic, vec![5; terra_limits::MAX_DEVICES]);
        assert!(
            controller
                .line(u8::try_from(terra_limits::MAX_DEVICES - 1).unwrap(), true)
                .is_ok()
        );
        assert!(matches!(
            Controller::new(Config {
                mode: Mode::Ioapic,
                routes: vec![24],
            }),
            Err(Error::InvalidSlot)
        ));
        assert!(matches!(
            Controller::new(Config {
                mode: Mode::Ioapic,
                routes: vec![5; terra_limits::MAX_DEVICES + 1],
            }),
            Err(Error::InvalidSlot)
        ));
        assert_eq!(controller.line(u8::MAX, true), Err(Error::InvalidSlot));
        for (offset, width) in [(4, 4), (0, 1)] {
            assert_eq!(
                controller.access(offset, width, false, 0),
                IoapicReply {
                    value: 0,
                    interrupts: Vec::new(),
                }
            );
        }
    }
}
