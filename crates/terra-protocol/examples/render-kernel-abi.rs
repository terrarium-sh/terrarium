//! Prints the kernel ABI header; `make kernel-abi` writes it to its checked-in path.

fn main() {
    print!("{}", terra_protocol::kernel_abi::render());
}
