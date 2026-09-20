//! Process-wide console logger for `lr-daemon`.
//!
//! The daemon has one thread per transport plus ticker, API, and metrics
//! threads. Standard output and standard error have independent locks, so
//! writes to the two streams can otherwise be interleaved by the console.

use std::fmt;
use std::io::{self, Write};
use std::sync::Mutex;

static CONSOLE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}

/// Write exactly one complete console record while holding the process-wide
/// output lock. A poisoned lock must not disable operational diagnostics.
pub(crate) fn write_line(stream: Stream, args: fmt::Arguments<'_>) {
    let _guard = CONSOLE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match stream {
        Stream::Stdout => {
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{args}");
        }
        Stream::Stderr => {
            let mut out = io::stderr().lock();
            let _ = writeln!(out, "{args}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logger_accepts_records_from_many_threads() {
        let handles: Vec<_> = (0..4)
            .map(|worker| {
                std::thread::spawn(move || {
                    for record in 0..2 {
                        write_line(
                            Stream::Stdout,
                            format_args!("logger-test worker={worker} record={record}"),
                        );
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }
}
