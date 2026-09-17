//! Canonical #813 dispatcher. Accepted-but-unused flags are intentional.
use crate::{
    formats::expand,
    state::{MultiplexerState, Rect, Result},
};
use std::collections::BTreeMap;

#[derive(Default)]
pub struct ClientFlags {
    pub no_output: bool,
    pub pause: Option<u32>,
    pub wait_exit: bool,
}
struct Args {
    flags: BTreeMap<char, Vec<String>>,
    words: Vec<String>,
}
impl Args {
    fn parse(tokens: &[String], values: &str) -> Self {
        let mut args = Self {
            flags: BTreeMap::new(),
            words: Vec::new(),
        };
        let mut tokens = tokens.iter().peekable();
        while let Some(token) = tokens.next() {
            if token == "--" {
                args.words.extend(tokens.cloned());
                break;
            }
            if token.starts_with('-') && !token.starts_with("--") && token.len() > 1 {
                let mut chars = token[1..].chars();
                while let Some(flag) = chars.next() {
                    let entry = args.flags.entry(flag).or_default();
                    if values.contains(flag) {
                        if !chars.as_str().is_empty() {
                            entry.push(chars.as_str().into());
                            break;
                        }
                        if tokens
                            .peek()
                            .is_some_and(|t| !t.starts_with('-') || t.len() == 1)
                        {
                            entry.push(tokens.next().unwrap().clone());
                            break;
                        }
                    }
                }
            } else {
                args.words.push(token.clone());
            }
        }
        args
    }
    fn has(&self, key: char) -> bool {
        self.flags.contains_key(&key)
    }
    fn get(&self, key: char) -> Option<&str> {
        self.flags
            .get(&key)
            .and_then(|v| v.last())
            .map(String::as_str)
    }
    fn word(&self) -> &str {
        self.words.first().map(String::as_str).unwrap_or_default()
    }
}

pub fn format(state: &MultiplexerState, template: &str, window: u32, pane: u32) -> Result<String> {
    expand(
        state,
        template,
        state.windows[&window].session,
        Some(window),
        Some(pane),
    )
}
fn values(name: &str) -> &'static str {
    match name {
        "refresh-client" | "refresh" => "CABfFrt",
        "capture-pane" | "capturep" => "tSEb",
        "send-keys" | "send" | "display-message" | "display" | "copy-mode" => "t",
        "list-windows" | "lsw" | "list-panes" | "lsp" | "list-sessions" | "list-session" | "ls" => {
            "Ftf"
        }
        "new-window" | "neww" | "split-window" | "splitw" => "tcFnl",
        "kill-pane" | "killp" | "kill-window" | "killw" | "select-pane" | "selectp"
        | "select-window" | "selectw" | "resize-pane" | "resizep" | "resize-window" | "resizew"
        | "rename-window" | "renamew" | "select-layout" | "selectl" => "tTxy",
        "attach-session" | "attach" | "new-session" | "new" | "kill-session" | "rename-session"
        | "rename" => "tsnc",
        "show-buffer" | "showb" | "set-buffer" | "setb" => "b",
        "swap-pane" | "swapp" | "move-pane" | "movep" | "break-pane" | "breakp" | "join-pane"
        | "joinp" => "stF",
        "show-options"
        | "show"
        | "show-option"
        | "set-option"
        | "set"
        | "show-window-options"
        | "showw"
        | "set-window-option"
        | "setw" => "to",
        "unlink-window" | "unlinkw" | "link-window" | "linkw" | "move-window" | "movew" => "st",
        _ => "tFcsnb",
    }
}
fn integer(s: &str, fallback: i32) -> i32 {
    let s = s.trim_ascii_start();
    let end = s
        .char_indices()
        .find(|(i, c)| !c.is_ascii_digit() && !(*i == 0 && matches!(c, '-' | '+')))
        .map_or(s.len(), |(i, _)| i);
    s[..end].parse().unwrap_or(fallback)
}
fn dimension(s: Option<&str>, fallback: u16, max: u16) -> Result<u16> {
    let n = integer(s.unwrap_or_default(), i32::from(fallback)).max(1);
    if n > i32::from(max) {
        Err(format!("size exceeds {max}"))
    } else {
        Ok(n as u16)
    }
}
fn list_row(output: &mut String, row: &str) -> Result<()> {
    if !output.is_empty() {
        crate::formats::append(output, "\n")?;
    }
    crate::formats::append(output, row)
}
pub fn execute(
    state: &mut MultiplexerState,
    flags: &mut ClientFlags,
    words: &[String],
) -> Result<Vec<u8>> {
    let name = words.first().ok_or("missing command")?.as_str();
    let args = Args::parse(&words[1..], values(name));
    let target = args.get('t');
    let session_target = target.or_else(|| args.get('s'));
    let mut output = String::new();
    match name {
        "display-message" | "display" => {
            let mut s = state.active; let mut w = state.active_window(); let mut p = state.active_pane();
            if let Some(t) = target {
                if t.starts_with('%') { let id = state.parse_pane_target(target)?; if state.panes.contains_key(&id) { p = id; w = state.window_of(p)?; } }
                else if t.starts_with('@') { let id = state.parse_window_target(target)?; if state.windows.contains_key(&id) { w = id; p = state.windows[&w].active; } }
                else if t.starts_with('$') { let id = state.parse_session_target(target)?; if state.sessions.contains_key(&id) { s = id; w = state.sessions[&s].active; p = state.windows[&w].active; } }
            }
            if args.has('p') { output = expand(state, args.words.first().map(String::as_str).unwrap_or("#{pane_id}"), s, Some(w), Some(p))?; }
        }
        "list-sessions" | "list-session" | "ls" => {
            for &s in state.sessions.keys() { list_row(&mut output, &expand(state, args.get('F').filter(|s| !s.is_empty()).unwrap_or("#{session_id} #{session_name}"), s, None, None)?)?; }
        }
        "list-windows" | "lsw" => {
            let s = if state.parse_session_target(session_target)? == 0 { state.active } else { state.session_target(session_target)? };
            for &w in &state.sessions[&s].windows {
                list_row(&mut output, &format(state, args.get('F').filter(|s| !s.is_empty()).unwrap_or("#{window_id} #{window_layout} #{window_flags} #{window_visible_layout}"), w, state.windows[&w].active)?)?;
            }
        }
        "list-panes" | "lsp" => {
            let id = if target.is_some_and(|t| t.starts_with('%')) { state.parse_pane_target(target)? } else { state.parse_window_target(target)? };
            let windows = if args.has('a') { state.sessions[&state.active].windows.clone() } else {
                // Canonical listPanes prefers a window with the same numeric ID
                // even if the original target was a pane.
                vec![if state.windows.contains_key(&id) { id } else { state.window_of(id).unwrap_or_else(|_| state.active_window()) }]
            };
            for w in windows {
                let mut chunk = String::new();
                for p in state.windows[&w].layout.panes() { list_row(&mut chunk, &format(state, args.get('F').filter(|s| !s.is_empty()).unwrap_or("#{pane_id} #{pane_width} #{pane_height}"), w, p)?)?; }
                if !chunk.is_empty() { list_row(&mut output, &chunk)?; }
            }
        }
        "new-window" | "neww" => {
            let w = state.new_window(args.get('n').map(str::to_owned), args.get('c').map(Into::into))?;
            if args.has('P') { output = format(state, args.get('F').unwrap_or("#{window_id}"), w, state.windows[&w].active)?; }
        }
        "split-window" | "splitw" => {
            let p = state.split(state.pane_target(target)?, args.has('h') && !args.has('v'), args.get('c').map(Into::into))?;
            if args.has('P') { output = expand(state, args.get('F').unwrap_or("#{pane_id}"), state.active, Some(state.window_of(p)?), Some(p))?; }
        }
        "send-keys" | "send" => {
            let p = state.pane_target(target)?;
            state.panes.get_mut(&p).unwrap().terminal.append_data(&encode_keys(&args.words, args.has('H'), args.has('l'))).map_err(|e| e.to_string())?;
        }
        "select-pane" | "selectp" => {
            let p = state.pane_target(target)?; let w = state.window_of(p)?;
            if args.has('T') { state.panes.get_mut(&p).unwrap().title = args.get('T').unwrap_or_default().into(); } else {
                state.windows.get_mut(&w).unwrap().active = p;
                let s = state.windows[&w].session; state.sessions.get_mut(&s).unwrap().active = w;
                state.notify(format!("%window-pane-changed @{w} %{p}\n"));
            }
        }
        "select-window" | "selectw" => {
            let w = state.window_target(target)?; let s = state.windows[&w].session;
            state.sessions.get_mut(&s).unwrap().active = w; state.notify(format!("%session-window-changed ${s} @{w}\n"));
        }
        "resize-pane" | "resizep" => {
            state.parse_pane_target(target)?;
            if !['Z','x','y','L','R','U','D'].into_iter().any(|flag| args.has(flag)) { return Ok(Vec::new()); }
            let p = state.pane_target(target)?; let w = state.window_of(p)?;
            if args.has('Z') {
                // #813 still uses zero as the zoom sentinel (unlike targets).
                let window = state.windows.get_mut(&w).unwrap(); window.zoom = if window.zoom.is_some() { None } else { (p != 0).then_some(p) };
                state.resize(w)?; state.layout_changed(w);
            } else if args.has('x') || args.has('y') {
                let cols = args.get('x').filter(|s| integer(s,0) > 0).map(|s| dimension(Some(s),1,512)).transpose()?;
                let rows = args.get('y').filter(|s| integer(s,0) > 0).map(|s| dimension(Some(s),1,256)).transpose()?;
                state.resize_pane(p,cols,rows)?;
            } else if let Some(dir) = ['L','R','U','D'].into_iter().find(|&c| args.has(c)) { state.resize_direction(p,dir,integer(args.word(),1))?; }
        }
        "resize-window" | "resizew" => {
            let w = state.window_target(target)?;
            let cols = dimension(args.get('x'),state.client_size.0,512)?; let rows = dimension(args.get('y'),state.client_size.1,256)?;
            state.windows.get_mut(&w).unwrap().rect = Rect { cols,rows,x:0,y:0 }; state.resize(w)?; state.layout_changed(w);
        }
        "kill-pane" | "killp" => { state.close(state.parse_pane_target(target)?)?; }
        "kill-window" | "killw" | "unlink-window" | "unlinkw" => { state.close_window(state.parse_window_target(target)?); }
        "select-layout" | "selectl" => {
            let w = state.window_target(target)?;
            if state.windows[&w].layout.panes().len() > 1 { state.windows.get_mut(&w).unwrap().layout.select(if args.word().is_empty() { "tiled" } else { args.word() }); state.resize(w)?; state.layout_changed(w); }
        }
        "swap-pane" | "swapp" => { state.swap(state.parse_pane_target(args.get('s'))?,state.parse_pane_target(target)?)?; }
        "move-pane" | "movep" | "join-pane" | "joinp" => { state.move_pane(state.parse_pane_target(args.get('s'))?,state.parse_pane_target(target)?,args.has('h') && !args.has('v'),args.has('b'))?; }
        "break-pane" | "breakp" => {
            let p = state.parse_pane_target(args.get('s').filter(|s| !s.is_empty()).or(target.filter(|s| !s.is_empty())).or_else(|| args.words.first().map(String::as_str)))?;
            let w = state.break_pane(p)?;
            if args.has('P') { let w = if state.windows.contains_key(&w) { w } else { state.active_window() }; output = expand(state,args.get('F').unwrap_or("#{window_id}"),state.active,Some(w),Some(state.windows[&w].active))?; }
        }
        "move-window" | "movew" => { state.move_window(state.parse_window_target(args.get('s'))?,state.parse_session_target(target)?); }
        "new-session" | "new" => {
            let id = state.new_session(args.get('s').unwrap_or_default().into())?;
            if !args.has('d') { state.active = id; session_changed(state); }
        }
        "attach-session" | "attach" => { state.active = state.session_target(session_target)?; session_changed(state); }
        "rename-session" | "rename" => {
            let s = state.session_target(session_target)?; state.sessions.get_mut(&s).unwrap().name = args.word().into();
            state.notify(format!("%session-renamed ${s} {}\n",safe(args.word())));
        }
        "kill-session" => { let s = state.parse_session_target(session_target)?; if let Some(session) = state.sessions.get(&s) { for w in session.windows.clone() { state.close_window(w); } state.notify("%sessions-changed\n".into()); } }
        "rename-window" | "renamew" => {
            let w = state.window_target(target)?; let window = state.windows.get_mut(&w).unwrap(); window.name = args.word().into(); window.automatic_rename = false;
            state.notify(format!("%window-renamed @{w} {}\n",safe(args.word())));
        }
        "set-buffer" | "setb" => {
            let name = args.get('b').unwrap_or("buffer0");
            if state.buffers.len() >= 32 && !state.buffers.contains_key(name) { return Err("buffer limit reached".into()); }
            state.buffers.insert(name.into(),args.word().into()); state.notify(format!("%paste-buffer-changed {}\n",safe(name)));
        }
        "show-buffer" | "showb" => { output = state.buffers.get(args.get('b').unwrap_or("buffer0")).cloned().unwrap_or_default(); }
        "set-option" | "set" | "set-window-option" | "setw" | "show-options" | "show" | "show-option" | "show-window-options" | "showw" => {
            let (scope,id) = if args.has('p') { ('p',state.parse_pane_target(target)?) } else if args.has('w') || name.contains("window") || matches!(name,"setw"|"showw") { ('w',state.parse_window_target(target)?) } else if args.has('g') { ('g',0) } else if args.has('s') { ('s',0) } else { (' ',state.parse_session_target(target)?) };
            if match scope { 'p' => !state.panes.contains_key(&id), 'w' => !state.windows.contains_key(&id), ' ' => !state.sessions.contains_key(&id), _ => false } { return Ok(Vec::new()); }
            let key = args.get('o').filter(|s| !s.is_empty()).unwrap_or(args.word());
            if !key.starts_with('@') { return Ok(Vec::new()); }
            let entry = (scope,id,key.to_owned());
            if name.starts_with("show") {
                if let Some(value) = state.options.get(&entry).filter(|v| !v.is_empty()) { output = if args.has('v') { value.clone() } else { format!("{key} {value}") }; }
            } else if args.has('u') { state.options.remove(&entry); } else {
                let value = args.words.get(usize::from(args.get('o').is_none_or(str::is_empty))).cloned().unwrap_or_default();
                if state.options.len() >= 256 && !state.options.contains_key(&entry) { return Err("option limit reached".into()); }
                let value = if args.has('a') { format!("{}{value}",state.options.get(&entry).cloned().unwrap_or_default()) } else { value };
                if value.len() > 65536 { return Err("option too long".into()); }
                state.options.insert(entry,value);
            }
        }
        "refresh-client" | "refresh" => {
            if args.has('C') {
                let spec = args.get('C').unwrap_or_default();
                let (target,size) = if spec.starts_with('@') { spec.split_once(':').map_or((None,spec),|(t,s)| (Some(t),s)) } else { (None,spec) };
                let (cols,rows) = if let Some((x,y)) = size.split_once('x').or_else(|| size.split_once(',')) { (dimension(Some(x),state.client_size.0,512)?,dimension(Some(y),state.client_size.1,256)?) } else { state.client_size };
                let wid = target.map(|t| crate::state::numeric_id(&t[1..])).transpose()?;
                // #813's refresh parser still uses 0 for unspecified (unlike
                // list/display target handling): @0 sizes the entire client.
                let windows = if let Some(w) = wid.filter(|&w| w != 0) { state.windows.get(&w).ok_or("can't find window")?; vec![w] } else { state.client_size = (cols,rows); state.sessions[&state.active].windows.clone() };
                for w in windows { state.windows.get_mut(&w).unwrap().rect = Rect { cols,rows,x:0,y:0 }; state.resize(w)?; state.layout_changed(w); }
            }
            if let Some(value) = args.get('f').or_else(|| args.get('F')) {
                for spec in value.split(',') {
                    let off = spec.starts_with('!'); let spec = spec.strip_prefix('!').unwrap_or(spec);
                    let (key,val) = spec.split_once('=').unwrap_or((spec,""));
                    match key { "no-output" => flags.no_output = !off, "wait-exit" => flags.wait_exit = !off, "pause-after" => { let n = integer(val,0); flags.pause = (!off && n >= 0).then_some(n as u32); }, _ => {} }
                }
            }
            for value in args.flags.get(&'A').into_iter().flatten() {
                let Some((target,action)) = value.split_once(':') else { continue; };
                let p = state.parse_pane_target(Some(target))?;
                if matches!(action,"pause"|"off") {
                    if state.pane_gates.len() >= 4096 && !state.pane_gates.contains_key(&p) { return Err("pane gate limit reached".into()); }
                    state.pane_gates.insert(p, true);
                } else { state.pane_gates.remove(&p); }
                if action == "continue" { state.notify(format!("%continue %{p}\n")); }
            }
        }
        "capture-pane" | "capturep" => {
            let p = state.parse_pane_target(target)?;
            if !state.panes.contains_key(&p) || !args.has('p') || (args.has('P') && args.has('C')) { return Ok(Vec::new()); }
            let bytes = state.panes.get_mut(&p).unwrap().screen.capture(&crate::screen::Capture { styled: args.has('e'), alternate: args.has('a'), start: integer(args.get('S').unwrap_or_default(),0), end: integer(args.get('E').unwrap_or_default(),0), join: args.has('J'), trailing: args.has('N') })?;
            return Ok(if args.has('C') { crate::framing::escape(&bytes) } else { bytes });
        }
        "list-commands" | "lscm" => output = "kill-pane [-a] [-t target-pane]\nnew-window [-adkP] [-c start-directory] [-n window-name] [-t target-window]\nrefresh-client [-C XxY] [-t target-client]\nresize-pane [-DLRTUZ] [-x width] [-y height] [-t target-pane]\nresize-window [-aADLTUx] [-x width] [-y height] [-t target-window]\nsend-keys [-Hl] [-t target-pane] key ...\nsplit-window [-bdfhvP] [-c start-directory] [-t target-pane]".into(),
        "link-window" | "linkw" | "copy-mode" | "list-keys" | "lsk" | "list-clients" | "lsc" | "phony-command" | "clear-history" | "clearhist" => {}
        _ => return Err(format!("parse error: unknown command: {name}")),
    }
    if matches!(
        name,
        "list-sessions" | "list-session" | "ls" | "list-windows" | "lsw" | "list-panes" | "lsp"
    ) && !output.is_empty()
        && !output.ends_with('\n')
    {
        crate::formats::append(&mut output, "\n")?;
    }
    Ok(output.into_bytes())
}
fn safe(s: &str) -> String {
    String::from_utf8_lossy(&crate::framing::escape(s.as_bytes())).into_owned()
}
pub fn session_changed(state: &mut MultiplexerState) {
    let id = state.active;
    state.notify(format!(
        "%session-changed ${id} {}\n",
        safe(&state.sessions[&id].name)
    ));
}
pub fn encode_keys(words: &[String], hex: bool, literal: bool) -> Vec<u8> {
    fn hex_byte(s: &str) -> Option<u8> {
        let s = s.trim_ascii_start();
        let negative = s.starts_with('-');
        let s = s.strip_prefix(['-', '+']).unwrap_or(s);
        let digits = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        let end = digits
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(digits.len());
        // scanf("%x") accepts the initial zero of a malformed 0x token.
        if end == 0 {
            return s.starts_with('0').then_some(0);
        }
        // Overflow saturates before sign conversion in the canonical libc
        // scanner; a negative overflowing token is not wrapped back to one.
        let Ok(value) = u64::from_str_radix(&digits[..end], 16) else {
            return Some(u8::MAX);
        };
        Some(if negative {
            value.wrapping_neg()
        } else {
            value
        } as u8)
    }
    let mut out = Vec::new();
    for word in words {
        if hex {
            out.push(hex_byte(word).unwrap_or(0));
        } else if literal {
            out.extend_from_slice(word.as_bytes());
        } else {
            match word.as_str() {
                "Enter" | "C-m" | "KPEnter" => out.push(b'\r'),
                "Escape" | "C-[" | "Esc" => out.push(27),
                "Space" => out.push(b' '),
                "Tab" | "C-i" => out.push(b'\t'),
                "BSpace" | "Bspace" => out.push(127),
                _ if word.len() == 3
                    && word.starts_with("C-")
                    && word.as_bytes()[2].is_ascii_alphabetic() =>
                {
                    out.push(word.as_bytes()[2] & 31)
                }
                _ if word.len() >= 3
                    && (word.starts_with("0x") || word.starts_with("0X"))
                    && hex_byte(word).is_some() =>
                {
                    out.push(hex_byte(word).unwrap())
                }
                _ => out.extend_from_slice(word.as_bytes()),
            }
        }
    }
    out
}
