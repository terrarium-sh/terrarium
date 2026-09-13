//! One file per command: each holds its `run` and the machinery only it uses.

pub mod detach;
pub mod exec;
pub mod logs;
pub mod ls;
pub mod put_get;
pub mod rm;
pub mod sessions;
pub mod setup;
pub mod show;
pub mod start;
pub mod stop;
pub mod storage;

#[cfg(test)]
struct InterruptedOnce(bool);

#[cfg(test)]
impl std::io::Read for InterruptedOnce {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        if std::mem::replace(&mut self.0, false) {
            Err(std::io::ErrorKind::Interrupted.into())
        } else {
            Ok(0)
        }
    }
}
