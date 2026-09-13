# WASI interface provenance

These interfaces come from WebAssembly/WASI v0.3.1, commit
`59e48bfe3fae9bf2480eb15abd8f55999eb3b395`:
https://github.com/WebAssembly/WASI/tree/59e48bfe3fae9bf2480eb15abd8f55999eb3b395/proposals

Each package combines its upstream `wit/*.wit` files in filename order with
one package declaration and trailing whitespace removed. Definitions and
version annotations are unchanged.
The upstream license is reproduced in `packaging/licenses/WASI-W3C.txt`.

Terra pins and verifies its runtime/binding compatibility in
the root `README.dev.md` (Component toolchain) and the component integration tests.
