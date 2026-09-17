//! Canonical libvterm in an import-free, fuel/memory bounded Wasm instance.
//! No guest pointer is dereferenced by the host. A trapped instance is poisoned.
use crate::state::Result;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    OnceLock,
};
use wasmi::{Config, Engine, Instance, Linker, Memory, Module, ResourceLimiter, Store};

const PANE_MEMORY: usize = 64 * 1024 * 1024;
const DAEMON_MEMORY: usize = 512 * 1024 * 1024;
static MEMORY: AtomicUsize = AtomicUsize::new(0);
static MODULE: OnceLock<Result<(Engine, Module)>> = OnceLock::new();

#[derive(Default)]
struct Budget {
    reserved: usize,
}
impl Drop for Budget {
    fn drop(&mut self) {
        MEMORY.fetch_sub(self.reserved, Ordering::Relaxed);
    }
}
impl ResourceLimiter for Budget {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmi_core::LimiterError> {
        if desired > PANE_MEMORY || maximum.is_some_and(|max| desired > max) {
            return Ok(false);
        }
        let growth = desired.saturating_sub(self.reserved);
        if MEMORY
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                total.checked_add(growth).filter(|&n| n <= DAEMON_MEMORY)
            })
            .is_err()
        {
            return Ok(false);
        }
        self.reserved += growth;
        Ok(true)
    }
    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmi_core::LimiterError> {
        Ok(desired <= 1024)
    }
    fn instances(&self) -> usize {
        1
    }
    fn tables(&self) -> usize {
        1
    }
    fn memories(&self) -> usize {
        1
    }
}

pub struct PaneScreen {
    store: Store<Budget>,
    instance: Instance,
    memory: Memory,
    input: usize,
    output: usize,
    metadata: [u16; 8],
    failed: bool,
}
#[derive(Default)]
pub struct Capture {
    pub styled: bool,
    pub alternate: bool,
    pub start: i32,
    pub end: i32,
    pub join: bool,
    pub trailing: bool,
}
impl PaneScreen {
    pub fn new(cols: u16, rows: u16) -> Result<Self> {
        let (engine, module) = MODULE
            .get_or_init(|| {
                let mut config = Config::default();
                config.consume_fuel(true);
                let engine = Engine::new(&config);
                let module = Module::new(&engine, include_bytes!("../screen-guest/screen.wasm"))
                    .map_err(|e| e.to_string())?;
                if module.imports().next().is_some() {
                    return Err("screen guest must have no imports".into());
                }
                Ok((engine, module))
            })
            .as_ref()
            .map_err(Clone::clone)?;
        let mut store = Store::new(engine, Budget::default());
        store.limiter(|b| b);
        store.set_fuel(100_000_000).map_err(|e| e.to_string())?;
        let instance = Linker::new(engine)
            .instantiate_and_start(&mut store, module)
            .map_err(|e| e.to_string())?;
        instance
            .get_typed_func::<(), ()>(&store, "_initialize")
            .map_err(|e| e.to_string())?
            .call(&mut store, ())
            .map_err(|e| e.to_string())?;
        instance
            .get_typed_func::<(i32, i32), ()>(&store, "init")
            .map_err(|e| e.to_string())?
            .call(&mut store, (cols.into(), rows.into()))
            .map_err(|e| e.to_string())?;
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or("screen memory export missing")?;
        let input = instance
            .get_typed_func::<(), i32>(&store, "input")
            .map_err(|e| e.to_string())?
            .call(&mut store, ())
            .map_err(|e| e.to_string())? as usize;
        let output = instance
            .get_typed_func::<(), i32>(&store, "output")
            .map_err(|e| e.to_string())?
            .call(&mut store, ())
            .map_err(|e| e.to_string())? as usize;
        let mut screen = Self {
            store,
            instance,
            memory,
            input,
            output,
            metadata: [0; 8],
            failed: false,
        };
        screen.update_metadata()?;
        Ok(screen)
    }
    fn call<P: wasmi::WasmParams, R: wasmi::WasmResults>(
        &mut self,
        name: &str,
        params: P,
    ) -> Result<R> {
        if self.failed {
            return Err("pane screen is poisoned".into());
        }
        let result = self
            .instance
            .get_typed_func::<P, R>(&self.store, name)
            .and_then(|func| func.call(&mut self.store, params));
        result.map_err(|e| {
            self.failed = true;
            format!("pane screen {name}: {e}")
        })
    }
    fn fuel(&mut self, amount: u64) -> Result<()> {
        self.store.set_fuel(amount).map_err(|e| e.to_string())
    }
    fn update_metadata(&mut self) -> Result<()> {
        for key in 0..8 {
            let value: i32 = self.call("metadata", key)?;
            self.metadata[key as usize] = value as u16;
        }
        Ok(())
    }
    pub fn process(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 65536 {
            return Err("screen feed exceeds 64 KiB".into());
        }
        self.fuel(20_000_000 + bytes.len() as u64 * 5000)?;
        self.memory
            .write(&mut self.store, self.input, bytes)
            .map_err(|e| e.to_string())?;
        self.call::<_, ()>("feed", bytes.len() as i32)?;
        self.update_metadata()
    }
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.fuel(100_000_000)?;
        self.call::<_, ()>("resize", (i32::from(cols), i32::from(rows)))?;
        self.update_metadata()
    }
    pub fn capture(&mut self, args: &Capture) -> Result<Vec<u8>> {
        self.fuel(200_000_000)?;
        let flags = i32::from(args.styled)
            | (i32::from(args.alternate) << 1)
            | (i32::from(args.join) << 2)
            | (i32::from(args.trailing) << 3);
        let len: i32 = self.call("capture", (flags, args.start, args.end))?;
        if len == -1 {
            return Err("capture exceeds reply size limit".into());
        }
        if !(0..=131072).contains(&len) {
            self.failed = true;
            return Err("invalid screen output length".into());
        }
        let mut bytes = vec![0; len as usize];
        self.memory
            .read(&self.store, self.output, &mut bytes)
            .map_err(|e| e.to_string())?;
        Ok(bytes)
    }
    pub fn cursor_position(&self) -> (u16, u16) {
        (self.metadata[1], self.metadata[0])
    }
    pub fn hide_cursor(&self) -> bool {
        self.metadata[2] == 0
    }
    pub fn alternate_screen(&self) -> bool {
        self.metadata[3] != 0
    }
    pub(crate) fn is_poisoned(&self) -> bool {
        self.failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "release-mode screen throughput/resource exercise"]
    fn sustained_output_remains_capturable() {
        let line = "0123456789".repeat(7) + "abcdefghi\r\n";
        let batch = line.repeat(768);
        let mut screen = PaneScreen::new(80, 24).unwrap();
        let started = std::time::Instant::now();
        for _ in 0..16 {
            screen.process(batch.as_bytes()).unwrap();
        }
        let elapsed = started.elapsed();
        let capture = screen.capture(&Capture::default()).unwrap();
        assert!(capture.starts_with((line.trim_end().to_owned() + "\n").as_bytes()));
        assert_eq!(screen.cursor_position(), (23, 0));
        assert!(screen
            .capture(&Capture {
                start: -2000,
                end: -1,
                trailing: true,
                ..Default::default()
            })
            .is_err());
        screen.process(b"still responsive").unwrap();
        assert!(screen
            .capture(&Capture::default())
            .unwrap()
            .windows(16)
            .any(|s| s == b"still responsive"));
        eprintln!("screen processed {} bytes in {elapsed:?}", batch.len() * 16);
    }

    #[test]
    fn oversized_capture_does_not_poison_a_valid_screen() {
        let mut screen = PaneScreen::new(512, 256).unwrap();
        assert!(screen
            .capture(&Capture {
                trailing: true,
                ..Default::default()
            })
            .is_err());
        screen.process(b"still alive").unwrap();
        assert!(screen
            .capture(&Capture {
                start: 0,
                end: 1,
                ..Default::default()
            })
            .unwrap()
            .starts_with(b"still alive\n"));
    }

    #[test]
    fn imports_absent_and_guest_traps_do_not_damage_other_panes() {
        let mut first = PaneScreen::new(80, 24).unwrap();
        let mut second = PaneScreen::new(80, 24).unwrap();
        assert!(first
            .process(b"\x1b[0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0m")
            .is_err());
        assert!(first.process(b"must not resume").is_err());
        second.process(b"safe").unwrap();
        assert!(second
            .capture(&Capture::default())
            .unwrap()
            .starts_with(b"safe\n"));
    }
}
