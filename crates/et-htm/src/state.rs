//! Daemon-owned identities, sessions, PTYs and ordered window/layout state.
pub use crate::layout::Layout;
use crate::terminal_handler::TerminalHandler;
use std::collections::BTreeMap;
use std::path::PathBuf;
pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rect {
    pub cols: u16,
    pub rows: u16,
    pub x: u16,
    pub y: u16,
}
pub fn checksum(body: &str) -> String {
    let sum = body
        .bytes()
        .fold(0u16, |s, b| s.rotate_right(1).wrapping_add(u16::from(b)));
    format!("{sum:04x},{body}")
}
pub struct Pane {
    pub terminal: TerminalHandler,
    pub screen: crate::screen::PaneScreen,
    pub rect: Rect,
    pub title: String,
}
pub struct Window {
    pub session: u32,
    pub name: String,
    pub order: usize,
    pub automatic_rename: bool,
    pub layout: Layout,
    pub rect: Rect,
    pub active: u32,
    pub zoom: Option<u32>,
}
pub struct Session {
    pub name: String,
    pub active: u32,
    pub windows: Vec<u32>,
}
pub struct MultiplexerState {
    pub panes: BTreeMap<u32, Pane>,
    pub windows: BTreeMap<u32, Window>,
    pub sessions: BTreeMap<u32, Session>,
    pub active: u32,
    pub client_size: (u16, u16),
    pub options: BTreeMap<(char, u32, String), String>,
    pub buffers: BTreeMap<String, String>,
    pub notifications: Vec<u8>,
    pub pane_gates: BTreeMap<u32, bool>,
    next_pane: u32,
    next_window: u32,
    next_session: u32,
    initial_attach_sent: bool,
}
impl MultiplexerState {
    pub fn new() -> Result<Self> {
        let mut s = Self {
            panes: BTreeMap::new(),
            windows: BTreeMap::new(),
            sessions: BTreeMap::new(),
            active: 0,
            client_size: (80, 24),
            options: BTreeMap::new(),
            buffers: BTreeMap::new(),
            notifications: Vec::new(),
            pane_gates: BTreeMap::new(),
            next_pane: 0,
            next_window: 0,
            next_session: 1,
            initial_attach_sent: false,
        };
        s.new_session("htm".into())?;
        s.notifications.clear();
        Ok(s)
    }
    pub fn new_session(&mut self, name: String) -> Result<u32> {
        if self.sessions.len() >= 32 {
            return Err("session limit reached".into());
        }
        let id = self.next_session;
        self.next_session += 1;
        self.sessions.insert(
            id,
            Session {
                name: if name.is_empty() {
                    id.to_string()
                } else {
                    name
                },
                active: 0,
                windows: Vec::new(),
            },
        );
        let previous = self.active;
        self.active = id;
        let created = self.new_window(None, None);
        self.active = if previous == 0 { id } else { previous };
        if let Err(error) = created {
            self.sessions.remove(&id);
            return Err(error);
        }
        self.notify("%sessions-changed\n".into());
        Ok(id)
    }
    pub fn active_window(&self) -> u32 {
        self.sessions.get(&self.active).map_or(0, |s| s.active)
    }
    pub fn active_pane(&self) -> u32 {
        self.windows
            .get(&self.active_window())
            .map_or(0, |w| w.active)
    }
    pub fn session_target(&self, target: Option<&str>) -> Result<u32> {
        let id = self.parse_session_target(target)?;
        self.sessions
            .contains_key(&id)
            .then_some(id)
            .ok_or_else(|| format!("can't find session: ${id}"))
    }
    pub fn parse_session_target(&self, target: Option<&str>) -> Result<u32> {
        let t = target.unwrap_or_default();
        let id = if let Some(n) = t.strip_prefix('$') {
            numeric_id(n)?
        } else {
            self.sessions
                .iter()
                .find(|(_, s)| s.name == t)
                .map_or(self.active, |(&id, _)| id)
        };
        Ok(id)
    }
    pub fn window_of(&self, pane: u32) -> Result<u32> {
        self.windows
            .iter()
            .find(|(_, w)| w.layout.contains(pane))
            .map(|(&id, _)| id)
            .ok_or_else(|| format!("can't find pane: %{pane}"))
    }
    pub fn pane_target(&self, target: Option<&str>) -> Result<u32> {
        let id = self.parse_pane_target(target)?;
        self.panes
            .contains_key(&id)
            .then_some(id)
            .ok_or_else(|| format!("can't find pane: %{id}"))
    }
    pub fn parse_pane_target(&self, target: Option<&str>) -> Result<u32> {
        let t = target.unwrap_or_default();
        let id = if t.is_empty() {
            self.active_pane()
        } else if let Some(n) = t.strip_prefix('%') {
            numeric_id(n)?
        } else if let Some(n) = t.strip_prefix('@') {
            self.windows
                .get(&numeric_id(n)?)
                .ok_or("can't find window")?
                .active
        } else {
            let n = numeric_id(t)?;
            if self.panes.contains_key(&n) {
                n
            } else {
                self.active_pane()
            }
        };
        Ok(id)
    }
    pub fn window_target(&self, target: Option<&str>) -> Result<u32> {
        let id = self.parse_window_target(target)?;
        self.windows
            .contains_key(&id)
            .then_some(id)
            .ok_or_else(|| format!("can't find window: @{id}"))
    }
    pub fn parse_window_target(&self, target: Option<&str>) -> Result<u32> {
        let t = target.unwrap_or_default();
        let id = if let Some((_, n)) = t.split_once('@').filter(|(_, n)| !n.is_empty()) {
            numeric_id(n)?
        } else if t.starts_with('%') {
            self.window_of(self.pane_target(Some(t))?)?
        } else {
            self.active_window()
        };
        Ok(id)
    }
    fn spawn(&mut self, cwd: Option<PathBuf>) -> Result<u32> {
        if self.panes.len() >= 64 {
            return Err("pane limit reached".into());
        }
        let (cols, rows) = self.client_size;
        let screen = crate::screen::PaneScreen::new(cols, rows)?;
        let terminal =
            TerminalHandler::start_in_size(cwd, cols, rows).map_err(|e| e.to_string())?;
        let id = self.next_pane;
        self.next_pane += 1;
        self.panes.insert(
            id,
            Pane {
                terminal,
                screen,
                rect: Rect {
                    cols,
                    rows,
                    x: 0,
                    y: 0,
                },
                title: String::new(),
            },
        );
        Ok(id)
    }
    fn window_from_pane(&mut self, pane: u32, session: u32, name: Option<String>) -> Result<u32> {
        let id = self.next_window;
        self.next_window += 1;
        let order = self.sessions[&session].windows.len();
        self.windows.insert(
            id,
            Window {
                session,
                name: name
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| order.to_string()),
                order,
                automatic_rename: true,
                layout: Layout::Pane(pane),
                rect: Rect {
                    cols: self.client_size.0,
                    rows: self.client_size.1,
                    x: 0,
                    y: 0,
                },
                active: pane,
                zoom: None,
            },
        );
        let s = self.sessions.get_mut(&session).unwrap();
        s.windows.push(id);
        s.active = id;
        self.resize(id)?;
        if order > 0 {
            self.notify(format!("%session-window-changed ${session} @{id}\n"));
        }
        self.notify(format!("%window-add @{id}\n"));
        Ok(id)
    }
    pub fn new_window(&mut self, name: Option<String>, cwd: Option<PathBuf>) -> Result<u32> {
        let cwd = cwd.filter(|p| !p.as_os_str().is_empty()).or_else(|| {
            if self.sessions[&self.active].windows.is_empty() {
                return None;
            }
            self.panes
                .get(&self.active_pane())
                .map(|p| p.terminal.cwd())
        });
        let p = self.spawn(cwd)?;
        self.window_from_pane(p, self.active, name)
    }
    pub fn split(&mut self, source: u32, horizontal: bool, cwd: Option<PathBuf>) -> Result<u32> {
        let w = self.window_of(source)?;
        let cwd = cwd
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| self.panes[&source].terminal.cwd());
        let p = self.spawn(Some(cwd))?;
        let window = self.windows.get_mut(&w).unwrap();
        window.layout.insert(source, p, horizontal, None);
        window.active = p;
        self.resize(w)?;
        self.notify(format!("%window-pane-changed @{w} %{p}\n"));
        self.layout_changed(w);
        Ok(p)
    }
    pub fn resize(&mut self, id: u32) -> Result<()> {
        let w = &self.windows[&id];
        let mut geometry = Vec::new();
        if let Some(p) = w.zoom {
            geometry.push((p, w.rect));
        } else {
            w.layout.geometry(w.rect, &mut geometry);
        }
        for (id, rect) in geometry {
            let p = self.panes.get_mut(&id).unwrap();
            p.rect = rect;
            // A guest trap must not unwind a half-applied ownership change
            // (swap/move/new-session). Finish topology, then reap in poll.
            if p.screen.resize(rect.cols, rect.rows).is_err() {
                continue;
            }
            p.terminal
                .update_terminal_size(i32::from(rect.cols), i32::from(rect.rows));
        }
        Ok(())
    }
    pub fn resize_pane(&mut self, pane: u32, cols: Option<u16>, rows: Option<u16>) -> Result<()> {
        let id = self.window_of(pane)?;
        let window = self.windows.get_mut(&id).unwrap();
        let mut changed = matches!(window.layout, Layout::Pane(_));
        for (axis, desired) in [(true, cols), (false, rows)] {
            if let Some(want) = desired {
                match window
                    .layout
                    .absolute(pane, axis, want, &|id| self.panes[&id].rect)
                {
                    Some(did_change) => changed |= did_change,
                    None => {
                        let dimension = if axis {
                            &mut window.rect.cols
                        } else {
                            &mut window.rect.rows
                        };
                        changed |= *dimension != want;
                        *dimension = want;
                    }
                }
            }
        }
        if changed {
            self.resize(id)?;
            self.layout_changed(id);
        }
        Ok(())
    }
    pub fn resize_direction(&mut self, pane: u32, dir: char, amount: i32) -> Result<()> {
        let id = self.window_of(pane)?;
        let w = self.windows.get_mut(&id).unwrap();
        if w.layout
            .directional(pane, dir, amount, &|id| self.panes[&id].rect)
        {
            self.resize(id)?;
            self.layout_changed(id);
        }
        Ok(())
    }
    pub fn layout(&self, id: u32, visible: bool) -> String {
        let w = &self.windows[&id];
        if let Some(pane) = w.zoom.filter(|_| visible) {
            return checksum(&format!("{}x{},0,0,{pane}", w.rect.cols, w.rect.rows));
        }
        checksum(&w.layout.dump(&|pane| self.panes[&pane].rect))
    }
    pub fn layout_changed(&mut self, id: u32) {
        let w = &self.windows[&id];
        let flags = format!(
            "{}{}",
            if self.sessions[&w.session].active == id {
                "*"
            } else {
                ""
            },
            if w.zoom.is_some() { "Z" } else { "" }
        );
        self.notify(format!(
            "%layout-change @{id} {} {} {flags}\n",
            self.layout(id, false),
            self.layout(id, true)
        ));
    }
    pub fn notify(&mut self, text: String) {
        self.notifications.extend_from_slice(text.as_bytes());
    }
    /// Detach from the tree without dropping the PTY, for pane moves.
    fn unlink(&mut self, pane: u32) -> Result<(u32, bool)> {
        let id = self.window_of(pane)?;
        let w = self.windows.get_mut(&id).unwrap();
        if let Some(tree) = w.layout.clone().remove(pane) {
            w.layout = tree;
            if w.active == pane || w.zoom == Some(pane) {
                w.active = w.layout.panes()[0];
            }
            if w.zoom == Some(pane) {
                w.zoom = None;
            }
            Ok((id, false))
        } else {
            Ok((id, true))
        }
    }
    pub fn close(&mut self, pane: u32) -> Result<()> {
        if !self.panes.contains_key(&pane) {
            return Ok(());
        }
        let (id, empty) = self.unlink(pane)?;
        self.panes.remove(&pane);
        self.pane_gates.remove(&pane);
        self.options
            .retain(|(scope, target, _), _| *scope != 'p' || *target != pane);
        if empty {
            self.remove_window(id);
        } else {
            self.resize(id)?;
            self.layout_changed(id);
            self.notify(format!(
                "%window-pane-changed @{id} %{}\n",
                self.windows[&id].active
            ));
        }
        Ok(())
    }
    fn remove_window(&mut self, id: u32) {
        let Some(w) = self.windows.remove(&id) else {
            return;
        };
        self.options
            .retain(|(scope, target, _), _| *scope != 'w' || *target != id);
        let s = self.sessions.get_mut(&w.session).unwrap();
        s.windows.retain(|&w| w != id);
        if s.windows.is_empty() {
            self.notify(format!("%unlinked-window-close @{id}\n"));
            self.sessions.remove(&w.session);
            self.options
                .retain(|(scope, target, _), _| *scope != ' ' || *target != w.session);
            self.notify("%sessions-changed\n".into());
            if self.active == w.session {
                self.active = self.sessions.keys().next().copied().unwrap_or(0);
                if self.active != 0 {
                    crate::control::session_changed(self);
                }
            }
        } else {
            if s.active == id {
                s.active = *s.windows.last().unwrap();
                let active = s.active;
                self.notify(format!(
                    "%session-window-changed ${} @{active}\n",
                    w.session
                ));
            }
            self.notify(format!("%unlinked-window-close @{id}\n"));
        }
    }
    pub fn close_window(&mut self, id: u32) {
        if let Some(w) = self.windows.get(&id) {
            for p in w.layout.panes() {
                self.panes.remove(&p);
                self.pane_gates.remove(&p);
                self.options
                    .retain(|(scope, target, _), _| *scope != 'p' || *target != p);
            }
            self.remove_window(id);
        }
    }
    pub fn swap(&mut self, a: u32, b: u32) -> Result<()> {
        if a == b || !self.panes.contains_key(&a) || !self.panes.contains_key(&b) {
            return Ok(());
        }
        let wa = self.window_of(a)?;
        let wb = self.window_of(b)?;
        let ids = if wa == wb { vec![wa] } else { vec![wa, wb] };
        for id in ids {
            let w = self.windows.get_mut(&id).unwrap();
            w.layout.swap(a, b);
            if !w.layout.contains(w.active) {
                w.active = if id == wa { b } else { a };
            }
            if w.zoom.is_some_and(|p| !w.layout.contains(p)) {
                w.zoom = None;
            }
            self.resize(id)?;
            self.layout_changed(id);
        }
        Ok(())
    }
    pub fn move_pane(&mut self, src: u32, dest: u32, horizontal: bool, before: bool) -> Result<()> {
        if src == dest || !self.panes.contains_key(&src) || !self.panes.contains_key(&dest) {
            return Ok(());
        }
        let destination = self.window_of(dest)?;
        let (source, empty) = self.unlink(src)?;
        if !empty && source != destination {
            self.resize(source)?;
            self.layout_changed(source);
            self.notify(format!(
                "%window-pane-changed @{source} %{}\n",
                self.windows[&source].active
            ));
        }
        let w = self.windows.get_mut(&destination).unwrap();
        w.layout.insert(dest, src, horizontal, Some(before));
        w.active = src;
        self.resize(destination)?;
        self.layout_changed(destination);
        self.notify(format!("%window-pane-changed @{destination} %{src}\n"));
        if empty && source != destination {
            self.remove_window(source);
        }
        Ok(())
    }
    pub fn break_pane(&mut self, pane: u32) -> Result<u32> {
        if !self.panes.contains_key(&pane) {
            return Ok(0);
        }
        let source = self.window_of(pane)?;
        if self.windows[&source].layout.panes().len() == 1 {
            return Ok(source);
        }
        let session = self.windows[&source].session;
        self.unlink(pane)?;
        self.resize(source)?;
        self.layout_changed(source);
        let id = self.window_from_pane(pane, session, None)?;
        self.layout_changed(id);
        Ok(id)
    }
    pub fn move_window(&mut self, id: u32, session: u32) {
        if !self.windows.contains_key(&id) || !self.sessions.contains_key(&session) {
            return;
        }
        let old = self.windows[&id].session;
        let s = self.sessions.get_mut(&old).unwrap();
        s.windows.retain(|&w| w != id);
        if s.active == id {
            s.active = s.windows.last().copied().unwrap_or(0);
            if !s.windows.is_empty() {
                let active = s.active;
                self.notify(format!("%session-window-changed ${old} @{active}\n"));
            }
        }
        let w = self.windows.get_mut(&id).unwrap();
        w.session = session;
        w.order = self.sessions[&session].windows.len();
        let s = self.sessions.get_mut(&session).unwrap();
        s.windows.push(id);
        s.active = id;
        self.notify(format!("%session-window-changed ${session} @{id}\n"));
        if old != session && self.sessions[&old].windows.is_empty() {
            self.sessions.remove(&old);
            self.options
                .retain(|(scope, target, _), _| *scope != ' ' || *target != old);
            self.notify("%sessions-changed\n".into());
            if self.active == old {
                self.active = session;
                crate::control::session_changed(self);
            }
        }
    }
    pub fn poll(&mut self, no_output: bool, extended: bool, pause: bool) -> Vec<u8> {
        let mut output = Vec::new();
        let mut exited = Vec::new();
        for (&id, pane) in &mut self.panes {
            if pane.screen.is_poisoned() {
                exited.push(id);
                continue;
            }
            let bytes = pane.terminal.poll_user_terminal();
            if !bytes.is_empty() {
                if bytes
                    .chunks(65536)
                    .try_for_each(|chunk| pane.screen.process(chunk))
                    .is_err()
                {
                    exited.push(id);
                    continue;
                }
                if !no_output && !self.pane_gates.get(&id).copied().unwrap_or(false) {
                    output.extend_from_slice(
                        if extended {
                            format!("%extended-output %{id} 0 : ")
                        } else {
                            format!("%output %{id} ")
                        }
                        .as_bytes(),
                    );
                    output.extend(crate::framing::escape(&bytes));
                    output.push(b'\n');
                    if pause {
                        self.pane_gates.insert(id, true);
                        output.extend_from_slice(format!("%pause %{id}\n").as_bytes());
                    }
                }
            } else if !pane.terminal.is_running() {
                exited.push(id);
            }
            if let Some((&wid, window)) = self
                .windows
                .iter_mut()
                .find(|(_, w)| w.active == id && w.automatic_rename)
            {
                let command = pane.terminal.foreground_command();
                if !command.is_empty() && command != window.name {
                    window.name = command;
                    self.notifications
                        .extend_from_slice(format!("%window-renamed @{wid} ").as_bytes());
                    self.notifications
                        .extend(crate::framing::escape(window.name.as_bytes()));
                    self.notifications.push(b'\n');
                }
            }
        }
        for id in exited {
            let _ = self.close(id);
        }
        output
    }
    pub fn stop_all(&mut self) {
        self.panes.clear();
    }
    pub fn attach_notifications(&mut self) {
        let Some(session) = self.sessions.get(&self.active) else {
            return;
        };
        if !self.initial_attach_sent {
            for id in session.windows.clone() {
                self.notify(format!("%window-add @{id}\n"));
            }
            self.notify("%sessions-changed\n".into());
            self.initial_attach_sent = true;
        }
        crate::control::session_changed(self);
    }
    /// Canonical GUI-oracle snapshot. The caller owns authenticated delivery;
    /// never create upstream's world-accessible predictable temporary dump.
    pub fn dump_panes(&mut self) -> Result<String> {
        let raw = self
            .options
            .get(&(' ', self.active, "@affinities".into()))
            .filter(|v| !v.is_empty())
            .or_else(|| self.options.get(&('g', 0, "@affinities".into())))
            .cloned()
            .unwrap_or_default();
        let decoded = raw.strip_prefix("a_").and_then(|hex| {
            if hex.len() % 2 != 0 {
                return None;
            }
            hex.as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let hi = (pair[0] as char).to_digit(16)?;
                    let lo = (pair[1] as char).to_digit(16)?;
                    Some((hi * 16 + lo) as u8)
                })
                .collect::<Option<Vec<_>>>()
        });
        let decoded = decoded.as_deref().unwrap_or(raw.as_bytes());
        let mut groups: Vec<Vec<u32>> = decoded
            .split(|&c| c == b' ')
            .filter_map(|part| {
                let part = part.split(|&c| c == b';').next().unwrap_or_default();
                let mut ids: Vec<_> = part
                    .split(|&c| c == b',')
                    .filter_map(|value| {
                        if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                            return None;
                        }
                        std::str::from_utf8(value)
                            .ok()?
                            .parse::<u64>()
                            .ok()
                            .map(|v| v as u32)
                    })
                    .collect();
                ids.sort_unstable();
                (!ids.is_empty()).then_some(ids)
            })
            .collect();
        groups.sort_by_key(|group| group[0]);
        let groups = groups
            .iter()
            .map(|group| {
                format!(
                    "[{}]",
                    group
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let mut out = format!("# affinities: [{groups}]\n");
        for session in self.sessions.values() {
            for &wid in &session.windows {
                let window = &self.windows[&wid];
                for pid in window.layout.panes() {
                    let pane = self.panes.get_mut(&pid).unwrap();
                    let (y, x) = pane.screen.cursor_position();
                    out += &format!("--- window @{wid} name={} pane %{pid} active={} {}x{} cursor={x},{y} shell_pid={} current={}\n", window.name, u8::from(window.active == pid), pane.rect.cols, pane.rect.rows, pane.terminal.process_id().unwrap_or(0), u8::from(session.active == wid && window.active == pid));
                    let text = pane.screen.capture(&crate::screen::Capture {
                        start: -1000,
                        end: -1,
                        join: true,
                        trailing: true,
                        ..Default::default()
                    })?;
                    out += &String::from_utf8_lossy(&text);
                    if !text.ends_with(b"\n") {
                        out.push('\n');
                    }
                    if out.len() > crate::framing::MAX_QUEUE / 2 {
                        return Err("pane dump exceeds reply limit".into());
                    }
                }
            }
        }
        Ok(out)
    }
    pub fn detach(&mut self) {
        if let Some(value) = self
            .options
            .get(&(' ', self.active, "@affinities".into()))
            .filter(|s| !s.is_empty())
            .cloned()
        {
            self.options.insert(('g', 0, "@affinities".into()), value);
        }
    }
}
pub(crate) fn numeric_id(text: &str) -> Result<u32> {
    let text = text.trim_ascii_start();
    let negative = text.starts_with('-');
    let text = text.strip_prefix(['-', '+']).unwrap_or(text);
    let end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let value: u64 = text[..end].parse().map_err(|_| "invalid target id")?;
    #[cfg(windows)]
    if value > u64::from(u32::MAX) {
        return Err("invalid target id".into());
    }
    Ok(if negative {
        value.wrapping_neg()
    } else {
        value
    } as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn geometry_matches_tmux_separator_and_checksum() {
        let layout = Layout::Split {
            horizontal: true,
            children: vec![Layout::Pane(0), Layout::Pane(1)],
            sizes: vec![0.5, 0.5],
        };
        let mut panes = Vec::new();
        let body = layout.geometry(
            Rect {
                cols: 80,
                rows: 24,
                x: 0,
                y: 0,
            },
            &mut panes,
        );
        assert_eq!(checksum(&body), "8205,80x24,0,0{40x24,0,0,0,39x24,41,0,1}");
        assert_eq!(panes[1].1.x, 41);
        assert_eq!(checksum("80x24,0,0,0"), "b25d,80x24,0,0,0");
    }
}
