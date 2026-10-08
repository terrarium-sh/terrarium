//! Emulates the x86 interrupt controller without host authority.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "interrupt-controller", path: "wit", generate_all, additional_derives: [PartialEq, Eq] });
}

use bindings::exports::terra::interrupt_controller::controller::{
    Config, Error, IoapicReply, IrqLevel, Mode, X86Interrupt,
};
use std::sync::{LazyLock, Mutex};

const PINS: usize = terra_limits::X86_IOAPIC_PINS as usize;
const REGISTER_SELECT: u8 = 0;
const WINDOW: u8 = 0x10;
const REDIRECTION_BASE: u8 = 0x10;
const MASKED: u64 = 1 << 16;
const LEVEL_TRIGGERED: u64 = 1 << 15;

struct Controller {
    mode: Mode,
    routes: Vec<usize>,
    levels: Vec<bool>,
    register: u8,
    redirection: [u64; PINS],
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
            .map(|route| usize::try_from(route).map_err(|_| Error::InvalidSlot))
            .collect::<Result<Vec<_>, _>>()?;
        if routes.iter().any(|route| *route >= PINS) {
            return Err(Error::InvalidSlot);
        }
        Ok(Self {
            mode: config.mode,
            levels: vec![false; routes.len()],
            routes,
            register: 0,
            redirection: [MASKED; PINS],
            asserted: [false; PINS],
        })
    }

    fn access(
        &mut self,
        offset: u8,
        width: u8,
        write: bool,
        value: u32,
    ) -> Result<IoapicReply, Error> {
        if self.mode != Mode::Ioapic {
            return Err(Error::InvalidState);
        }
        if width != 4 {
            return Ok(IoapicReply {
                value: 0,
                interrupts: Vec::new(),
            });
        }
        match (offset, write) {
            (REGISTER_SELECT, false) => Ok(IoapicReply {
                value: u32::from(self.register),
                interrupts: Vec::new(),
            }),
            (REGISTER_SELECT, true) => {
                self.register = value.to_le_bytes()[0];
                Ok(IoapicReply {
                    value: 0,
                    interrupts: Vec::new(),
                })
            }
            (WINDOW, false) => Ok(IoapicReply {
                value: self.read_register(),
                interrupts: Vec::new(),
            }),
            (WINDOW, true) => Ok(IoapicReply {
                value: 0,
                interrupts: self
                    .write_register(value)
                    .filter(|pin| self.asserted[*pin])
                    .and_then(|pin| self.deliver(pin))
                    .into_iter()
                    .collect(),
            }),
            _ => Ok(IoapicReply {
                value: 0,
                interrupts: Vec::new(),
            }),
        }
    }

    fn line(
        &mut self,
        slot: u8,
        level: bool,
    ) -> Result<(Option<IrqLevel>, Vec<X86Interrupt>), Error> {
        let slot = usize::from(slot);
        let gsi = *self.routes.get(slot).ok_or(Error::InvalidSlot)?;
        if self.levels[slot] == level {
            return Ok((None, Vec::new()));
        }
        self.levels[slot] = level;
        let aggregated = self
            .routes
            .iter()
            .enumerate()
            .any(|(candidate, route)| *route == gsi && self.levels[candidate]);
        if self.asserted[gsi] == aggregated {
            return Ok((None, Vec::new()));
        }
        self.asserted[gsi] = aggregated;
        let change = IrqLevel {
            gsi: u32::try_from(gsi).map_err(|_| Error::InvalidSlot)?,
            asserted: aggregated,
        };
        let interrupts = aggregated
            .then(|| self.deliver(gsi))
            .flatten()
            .into_iter()
            .collect();
        Ok((Some(change), interrupts))
    }

    fn eoi(&self, vector: u8) -> Result<Vec<X86Interrupt>, Error> {
        if self.mode != Mode::Ioapic {
            return Err(Error::InvalidState);
        }
        Ok((0..PINS)
            .filter(|pin| {
                self.asserted[*pin]
                    && self.redirection[*pin].to_le_bytes()[0] == vector
                    && self.redirection[*pin] & LEVEL_TRIGGERED != 0
            })
            .filter_map(|pin| self.deliver(pin))
            .collect())
    }

    fn read_register(&self) -> u32 {
        match self.register {
            1 => ((terra_limits::X86_IOAPIC_PINS - 1) << 16) | 0x11,
            0 | 2 => 0,
            register if register >= REDIRECTION_BASE => {
                let entry = usize::from(register - REDIRECTION_BASE) / 2;
                if entry >= PINS {
                    return 0;
                }
                let bytes = self.redirection[entry].to_le_bytes();
                if (register - REDIRECTION_BASE).is_multiple_of(2) {
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                } else {
                    u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
                }
            }
            _ => 0,
        }
    }

    fn write_register(&mut self, value: u32) -> Option<usize> {
        if self.register < REDIRECTION_BASE {
            return None;
        }
        let entry = usize::from(self.register - REDIRECTION_BASE) / 2;
        if entry >= PINS {
            return None;
        }
        if (self.register - REDIRECTION_BASE).is_multiple_of(2) {
            self.redirection[entry] =
                (self.redirection[entry] & !u64::from(u32::MAX)) | u64::from(value);
        } else {
            self.redirection[entry] =
                (self.redirection[entry] & u64::from(u32::MAX)) | (u64::from(value) << 32);
        }
        Some(entry)
    }

    fn deliver(&self, pin: usize) -> Option<X86Interrupt> {
        let entry = self.redirection[pin];
        (entry & MASKED == 0).then_some(X86Interrupt {
            vector: entry.to_le_bytes()[0],
            destination: entry.to_le_bytes()[7],
            level_triggered: entry & LEVEL_TRIGGERED != 0,
        })
    }
}

static CONTROLLER: LazyLock<Mutex<Option<Controller>>> = LazyLock::new(|| Mutex::new(None));

fn controller() -> std::sync::MutexGuard<'static, Option<Controller>> {
    CONTROLLER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct Component;

#[allow(unsafe_code)]
mod component_exports {
    use super::{Component, bindings};
    bindings::export!(Component with_types_in bindings);
}

impl bindings::exports::terra::interrupt_controller::controller::Guest for Component {
    fn configure(config: Config) -> Result<(), Error> {
        let mut controller = controller();
        if controller.is_some() {
            return Err(Error::InvalidState);
        }
        *controller = Some(Controller::new(config)?);
        Ok(())
    }

    fn irq_line(slot: u8, asserted: bool) -> Result<Option<IrqLevel>, Error> {
        let mut state = controller();
        let controller = state.as_mut().ok_or(Error::InvalidState)?;
        if controller.mode != Mode::IrqLines {
            return Err(Error::InvalidState);
        }
        let (change, _) = controller.line(slot, asserted)?;
        Ok(change)
    }

    fn ioapic_line(slot: u8, asserted: bool) -> Result<Vec<X86Interrupt>, Error> {
        let mut state = controller();
        let controller = state.as_mut().ok_or(Error::InvalidState)?;
        if controller.mode != Mode::Ioapic {
            return Err(Error::InvalidState);
        }
        let (_, interrupts) = controller.line(slot, asserted)?;
        Ok(interrupts)
    }

    fn access(offset: u8, width: u8, write: bool, value: u32) -> Result<IoapicReply, Error> {
        controller()
            .as_mut()
            .ok_or(Error::InvalidState)?
            .access(offset, width, write, value)
    }

    fn eoi(vector: u8) -> Result<Vec<X86Interrupt>, Error> {
        controller()
            .as_ref()
            .ok_or(Error::InvalidState)?
            .eoi(vector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller(mode: Mode, routes: Vec<u32>) -> Controller {
        Controller::new(Config { mode, routes }).unwrap()
    }

    fn access(controller: &mut Controller, offset: u8, write: bool, value: u32) -> IoapicReply {
        controller.access(offset, 4, write, value).unwrap()
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
            controller.line(0, true).unwrap().1,
            vec![X86Interrupt {
                vector: 0x31,
                destination: 2,
                level_triggered: false,
            }]
        );
        assert_eq!(controller.line(1, true).unwrap().1, []);
        assert_eq!(controller.line(0, false).unwrap().0, None);
        assert_eq!(controller.line(1, false).unwrap().0.unwrap().gsi, 5);
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
        redirection(
            &mut controller,
            5,
            0x31 | u32::try_from(LEVEL_TRIGGERED).unwrap(),
            0,
        );
        let (_, delivered) = controller.line(0, true).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(controller.eoi(0x31).unwrap(), delivered);
        assert_eq!(controller.eoi(0x32).unwrap(), []);
    }

    #[test]
    fn writing_an_asserted_redirection_entry_redelivers_it() {
        let mut controller = controller(Mode::Ioapic, vec![5]);
        redirection(&mut controller, 5, 0x31, 0);
        assert_eq!(controller.line(0, true).unwrap().1.len(), 1);
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
                controller.access(offset, width, false, 0).unwrap(),
                IoapicReply {
                    value: 0,
                    interrupts: Vec::new(),
                }
            );
        }
    }
}
