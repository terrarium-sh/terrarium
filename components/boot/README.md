# Boot component

`terra-boot-component` plans the kernel entry, kernel segments, and boot data
for the configured x86 or Arm machine. The import-free component receives
machine configuration and the kernel prefix. The host validates the returned
plan and copies its bounded segments and writes into guest RAM.

See [the boot implementation](src/boot.rs), [the component entry point](src/lib.rs),
[boot.wit](wit/boot.wit), and the [authority inventory](../../docs/component-authority.md).
