const PINS: usize = 24;
const REGISTER_SELECT: u8 = 0;
const WINDOW: u8 = 0x10;
const REDIRECTION_BASE: u8 = 0x10;
const MASKED: u64 = 1 << 16;
const LEVEL_TRIGGERED: u64 = 1 << 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct X86Interrupt {
    pub(crate) vector: u8,
    pub(crate) destination: u8,
    pub(crate) level_triggered: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IoApicError {
    Unconfigured,
    InvalidSlot,
    BadOffset,
    BadWidth,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Access {
    pub(crate) value: u32,
    pub(crate) interrupts: Vec<X86Interrupt>,
}

pub(crate) struct IoApic {
    routes: Option<Vec<usize>>,
    levels: Vec<bool>,
    register: u8,
    redirection: [u64; PINS],
    asserted: [bool; PINS],
}

impl IoApic {
    pub(crate) const fn new() -> Self {
        Self {
            routes: None,
            levels: Vec::new(),
            register: 0,
            redirection: [MASKED; PINS],
            asserted: [false; PINS],
        }
    }

    pub(crate) fn configure(&mut self, routes: Vec<u32>) -> Result<(), IoApicError> {
        if routes.len() > super::MAX_DEVICES {
            return Err(IoApicError::InvalidSlot);
        }
        let routes = routes
            .into_iter()
            .map(|route| usize::try_from(route).map_err(|_| IoApicError::InvalidSlot))
            .collect::<Result<Vec<_>, _>>()?;
        if routes.iter().any(|route| *route >= PINS) {
            return Err(IoApicError::InvalidSlot);
        }
        self.levels = vec![false; routes.len()];
        self.routes = Some(routes);
        self.asserted = [false; PINS];
        Ok(())
    }

    pub(crate) fn access(
        &mut self,
        offset: u8,
        width: u8,
        write: bool,
        value: u32,
    ) -> Result<Access, IoApicError> {
        if width != 4 {
            return Err(IoApicError::BadWidth);
        }
        match (offset, write) {
            (REGISTER_SELECT, false) => Ok(Access {
                value: u32::from(self.register),
                interrupts: Vec::new(),
            }),
            (REGISTER_SELECT, true) => {
                self.register = value.to_le_bytes()[0];
                Ok(Access {
                    value: 0,
                    interrupts: Vec::new(),
                })
            }
            (WINDOW, false) => Ok(Access {
                value: self.read_register(),
                interrupts: Vec::new(),
            }),
            (WINDOW, true) => {
                let interrupts = self
                    .write_register(value)
                    .filter(|pin| self.asserted[*pin])
                    .and_then(|pin| self.deliver(pin))
                    .into_iter()
                    .collect();
                Ok(Access {
                    value: 0,
                    interrupts,
                })
            }
            _ => Err(IoApicError::BadOffset),
        }
    }

    pub(crate) fn set_line(
        &mut self,
        slot: u8,
        asserted: bool,
    ) -> Result<Vec<X86Interrupt>, IoApicError> {
        let routes = self.routes.as_ref().ok_or(IoApicError::Unconfigured)?;
        let slot = usize::from(slot);
        let gsi = *routes.get(slot).ok_or(IoApicError::InvalidSlot)?;
        if self.levels[slot] == asserted {
            return Ok(Vec::new());
        }
        self.levels[slot] = asserted;
        let aggregated = routes
            .iter()
            .enumerate()
            .any(|(candidate, route)| *route == gsi && self.levels[candidate]);
        if self.asserted[gsi] == aggregated {
            return Ok(Vec::new());
        }
        self.asserted[gsi] = aggregated;
        if aggregated {
            Ok(self.deliver(gsi).into_iter().collect())
        } else {
            Ok(Vec::new())
        }
    }

    pub(crate) fn eoi(&self, vector: u8) -> Vec<X86Interrupt> {
        (0..PINS)
            .filter(|pin| {
                self.asserted[*pin]
                    && self.redirection[*pin].to_le_bytes()[0] == vector
                    && self.redirection[*pin] & LEVEL_TRIGGERED != 0
            })
            .filter_map(|pin| self.deliver(pin))
            .collect()
    }

    fn read_register(&self) -> u32 {
        match self.register {
            1 => 0x0017_0011,
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

#[cfg(test)]
mod tests {
    use super::{IoApic, IoApicError, REDIRECTION_BASE, X86Interrupt};

    fn access(ioapic: &mut IoApic, offset: u8, write: bool, value: u32) -> u32 {
        ioapic.access(offset, 4, write, value).unwrap().value
    }

    fn select(ioapic: &mut IoApic, register: u8) {
        access(ioapic, 0, true, u32::from(register));
    }

    fn redirection(ioapic: &mut IoApic, pin: u8, low: u32, high: u32) {
        select(ioapic, REDIRECTION_BASE + pin * 2);
        access(ioapic, 0x10, true, low);
        select(ioapic, REDIRECTION_BASE + pin * 2 + 1);
        access(ioapic, 0x10, true, high);
    }

    #[test]
    fn redirection_entries_start_masked_and_keep_both_halves() {
        let mut ioapic = IoApic::new();
        select(&mut ioapic, REDIRECTION_BASE);
        assert_eq!(access(&mut ioapic, 0x10, false, 0), 1 << 16);
        access(&mut ioapic, 0x10, true, 0x31);
        select(&mut ioapic, REDIRECTION_BASE + 1);
        access(&mut ioapic, 0x10, true, 2);
        select(&mut ioapic, REDIRECTION_BASE);
        assert_eq!(access(&mut ioapic, 0x10, false, 0), 0x31);
        select(&mut ioapic, REDIRECTION_BASE + 1);
        assert_eq!(access(&mut ioapic, 0x10, false, 0), 2);
    }

    #[test]
    fn shared_route_delivers_only_on_aggregate_assertion() {
        let mut ioapic = IoApic::new();
        ioapic.configure(vec![5, 5]).unwrap();
        redirection(&mut ioapic, 5, 0x31, 2 << 24);
        let interrupt = X86Interrupt {
            vector: 0x31,
            destination: 2,
            level_triggered: false,
        };
        assert_eq!(ioapic.set_line(0, true).unwrap(), vec![interrupt]);
        assert_eq!(ioapic.set_line(1, true).unwrap(), []);
        assert_eq!(ioapic.set_line(0, false).unwrap(), []);
        assert_eq!(ioapic.set_line(1, false).unwrap(), []);
    }

    #[test]
    fn eoi_redelivers_asserted_level_interrupts() {
        let mut ioapic = IoApic::new();
        ioapic.configure(vec![5]).unwrap();
        redirection(&mut ioapic, 5, 0x31 | 1 << 15, 2 << 24);
        let interrupt = X86Interrupt {
            vector: 0x31,
            destination: 2,
            level_triggered: true,
        };
        assert_eq!(ioapic.set_line(0, true).unwrap(), vec![interrupt]);
        assert_eq!(ioapic.eoi(0x31), vec![interrupt]);
        assert_eq!(ioapic.eoi(0x32), []);
    }

    #[test]
    fn writing_an_asserted_redirection_entry_redelivers_it() {
        let mut ioapic = IoApic::new();
        ioapic.configure(vec![5]).unwrap();
        redirection(&mut ioapic, 5, 0x31, 0);
        assert_eq!(ioapic.set_line(0, true).unwrap().len(), 1);
        select(&mut ioapic, REDIRECTION_BASE + 5 * 2);
        assert_eq!(
            ioapic.access(0x10, 4, true, 0x32).unwrap().interrupts[0].vector,
            0x32
        );
    }

    #[test]
    fn shared_pins_support_every_device_slot() {
        let mut ioapic = IoApic::new();
        ioapic.configure(vec![5; crate::MAX_DEVICES]).unwrap();
        assert!(
            ioapic
                .set_line(u8::try_from(crate::MAX_DEVICES - 1).unwrap(), true)
                .is_ok()
        );
        assert_eq!(
            ioapic.configure(vec![5; crate::MAX_DEVICES + 1]),
            Err(IoApicError::InvalidSlot)
        );
    }

    #[test]
    fn rejects_invalid_ioapic_access_and_unconfigured_lines() {
        let mut ioapic = IoApic::new();
        assert_eq!(ioapic.set_line(0, true), Err(IoApicError::Unconfigured));
        assert_eq!(ioapic.access(4, 4, false, 0), Err(IoApicError::BadOffset));
        assert_eq!(ioapic.access(0, 1, false, 0), Err(IoApicError::BadWidth));
        assert_eq!(ioapic.configure(vec![24]), Err(IoApicError::InvalidSlot));
    }
}
