//! Windows output setup from upstream #741/#753. Input remains crossterm's
//! raw mode: in particular, do not re-enable processed input (Ctrl-C).
use std::io::{self, Write};

// Win32 output flags: ENABLE_PROCESSED_OUTPUT, ENABLE_WRAP_AT_EOL_OUTPUT,
// ENABLE_VIRTUAL_TERMINAL_PROCESSING, DISABLE_NEWLINE_AUTO_RETURN.
const REQUIRED_OUTPUT_MODE: u32 = 0x0001 | 0x0002 | 0x0004 | 0x0008;
const ENABLE_AUTOWRAP: &[u8] = b"\x1b[?7h";

pub(super) trait ConsoleMode {
    fn mode(&self) -> io::Result<u32>;
    fn set_mode(&self, mode: u32) -> io::Result<()>;
}

#[cfg(windows)]
impl ConsoleMode for crossterm_winapi::ConsoleMode {
    fn mode(&self) -> io::Result<u32> {
        self.mode()
    }

    fn set_mode(&self, mode: u32) -> io::Result<()> {
        self.set_mode(mode)
    }
}

/// Retains the same output handle and restores every inherited mode bit.
/// Drop this only after flushing terminal reset sequences.
pub(super) struct OutputMode<M: ConsoleMode> {
    console: M,
    inherited: u32,
}

impl<M: ConsoleMode> OutputMode<M> {
    pub(super) fn enter(console: M, writer: &mut impl Write) -> io::Result<Self> {
        let inherited = console.mode()?;
        let guard = Self { console, inherited };
        guard.console.set_mode(inherited | REQUIRED_OUTPUT_MODE)?;
        // Some hosts report autowrap enabled but still repaint long input on
        // one row after SetConsoleMode. Reassert it, keeping delayed newline
        // return enabled for tmux scrolling. Roll back even if write/flush fails.
        writer.write_all(ENABLE_AUTOWRAP)?;
        writer.flush()?;
        Ok(guard)
    }
}

impl<M: ConsoleMode> Drop for OutputMode<M> {
    fn drop(&mut self) {
        let _ = self.console.set_mode(self.inherited);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Clone)]
    struct FakeConsole(Rc<RefCell<(u32, Vec<u32>)>>);

    impl ConsoleMode for FakeConsole {
        fn mode(&self) -> io::Result<u32> {
            Ok(self.0.borrow().0)
        }

        fn set_mode(&self, mode: u32) -> io::Result<()> {
            let mut state = self.0.borrow_mut();
            state.0 = mode;
            state.1.push(mode);
            Ok(())
        }
    }

    struct Writer {
        console: FakeConsole,
        bytes: Vec<u8>,
        fail_write: bool,
        fail_flush: bool,
        flushed: bool,
    }

    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            assert_eq!(self.console.mode()?, 0x1f, "mode must precede DECAWM");
            if self.fail_write {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed = true;
            if self.fail_flush {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            Ok(())
        }
    }

    #[test]
    fn preserves_bits_orders_setup_and_restores_on_success_or_io_error() {
        for (fail_write, fail_flush) in [(false, false), (true, false), (false, true)] {
            // An unrelated bit set, all required bits initially absent.
            let console = FakeConsole(Rc::new(RefCell::new((0x10, vec![]))));
            let mut writer = Writer {
                console: console.clone(),
                bytes: vec![],
                fail_write,
                fail_flush,
                flushed: false,
            };
            let result = OutputMode::enter(console.clone(), &mut writer);
            assert_eq!(result.is_err(), fail_write || fail_flush);
            if !fail_write {
                assert_eq!(writer.bytes, b"\x1b[?7h");
                assert!(writer.flushed);
            }
            drop(result);
            assert_eq!(*console.0.borrow(), (0x10, vec![0x1f, 0x10]));
        }
    }

    #[test]
    fn console_api_errors_do_not_emit_decawm_or_panic_during_restore() {
        struct FailingConsole<'a> {
            fail_read: bool,
            attempts: &'a RefCell<Vec<u32>>,
        }
        impl ConsoleMode for FailingConsole<'_> {
            fn mode(&self) -> io::Result<u32> {
                if self.fail_read {
                    Err(io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok(0x12)
                }
            }
            fn set_mode(&self, mode: u32) -> io::Result<()> {
                self.attempts.borrow_mut().push(mode);
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        for fail_read in [true, false] {
            let attempts = RefCell::new(vec![]);
            let mut bytes = vec![];
            assert!(OutputMode::enter(
                FailingConsole {
                    fail_read,
                    attempts: &attempts
                },
                &mut bytes
            )
            .is_err());
            assert!(bytes.is_empty());
            assert_eq!(
                *attempts.borrow(),
                if fail_read { vec![] } else { vec![0x1f, 0x12] }
            );
        }
    }

    #[test]
    fn unwinding_restores_the_exact_inherited_mode() {
        let console = FakeConsole(Rc::new(RefCell::new((0x15, vec![]))));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = OutputMode::enter(console.clone(), &mut vec![]).unwrap();
            panic!("session failed");
        }));
        assert!(result.is_err());
        assert_eq!(*console.0.borrow(), (0x15, vec![0x1f, 0x15]));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an attached Windows console; run alone with --ignored --nocapture"]
    fn native_console_restores_output_and_leaves_raw_input_unchanged() {
        let input =
            crossterm_winapi::ConsoleMode::from(crossterm_winapi::Handle::input_handle().unwrap());
        let output = crossterm_winapi::ConsoleMode::new().unwrap();
        let inherited_input = input.mode().unwrap();
        let inherited_output = output.mode().unwrap();
        let raw = crate::client_terminal::RawMode::enter().unwrap();
        assert!(raw.enabled, "run attached to a console");
        // ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT.
        assert_eq!(input.mode().unwrap() & 0x7, 0);
        assert_eq!(output.mode().unwrap(), inherited_output | 0xf);
        drop(raw);
        assert_eq!(input.mode().unwrap(), inherited_input);
        assert_eq!(output.mode().unwrap(), inherited_output);
    }
}
