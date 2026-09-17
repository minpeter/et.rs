//! Canonical expand/expandOne semantics, with bounded recursive conditionals.
use crate::state::{MultiplexerState, Result};

pub(crate) fn append(out: &mut String, value: &str) -> Result<()> {
    if value.len() > (crate::framing::MAX_QUEUE / 2).saturating_sub(out.len()) {
        return Err("format exceeds reply size limit".into());
    }
    out.push_str(value);
    Ok(())
}

pub fn expand(
    state: &MultiplexerState,
    template: &str,
    session: u32,
    window: Option<u32>,
    pane: Option<u32>,
) -> Result<String> {
    expand_at(state, template, session, window, pane, 0)
}
fn expand_at(
    state: &MultiplexerState,
    template: &str,
    session: u32,
    window: Option<u32>,
    pane: Option<u32>,
    depth: usize,
) -> Result<String> {
    if depth >= 64 {
        return Err("format nesting limit reached".into());
    }
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("#{") {
        append(&mut out, &rest[..start])?;
        let inner = &rest[start + 2..];
        let mut nesting = 1;
        let end = inner.char_indices().find_map(|(i, c)| {
            match c {
                '{' => nesting += 1,
                '}' => nesting -= 1,
                _ => {}
            }
            (nesting == 0).then_some(i)
        });
        let Some(end) = end else {
            append(&mut out, &rest[start..])?;
            return Ok(out);
        };
        let key = inner[..end].strip_prefix("q:").unwrap_or(&inner[..end]);
        if let Some(condition) = key.strip_prefix('?') {
            let mut nesting = 0;
            let mut parts = Vec::new();
            let mut begin = 0;
            for (i, c) in condition.char_indices() {
                match c {
                    '{' => nesting += 1,
                    '}' => nesting -= 1,
                    ',' if nesting == 0 => {
                        parts.push(&condition[begin..i]);
                        begin = i + 1;
                    }
                    _ => {}
                }
            }
            parts.push(&condition[begin..]);
            let cond = parts[0];
            let value = if cond.contains("#{") {
                expand_at(state, cond, session, window, pane, depth + 1)?
            } else {
                one(state, cond, session, window, pane)
            };
            let chosen = parts
                .get(if value.is_empty() || value == "0" {
                    2
                } else {
                    1
                })
                .copied()
                .unwrap_or_default();
            append(
                &mut out,
                &expand_at(state, chosen, session, window, pane, depth + 1)?,
            )?;
        } else {
            append(&mut out, &one(state, key, session, window, pane))?;
        }
        rest = &inner[end + 1..];
    }
    append(&mut out, rest)?;
    Ok(out)
}
fn one(
    state: &MultiplexerState,
    key: &str,
    session: u32,
    window: Option<u32>,
    pane: Option<u32>,
) -> String {
    let s = state.sessions.get(&session);
    if key.starts_with('@') && s.is_some() {
        return state
            .options
            .get(&(' ', session, key.into()))
            .cloned()
            .unwrap_or_default();
    }
    match key {
        "version" => return "3.5a".into(),
        "socket_path" => return "htm".into(),
        "pid" => return "0".into(),
        "pane-border-status" | "pane_border_status" => return "off".into(),
        _ => {}
    }
    if let Some(s) = s {
        match key {
            "session_id" => return format!("${session}"),
            "session_name" => return s.name.clone(),
            _ => {}
        }
    }
    if let Some((id, w)) = window.and_then(|id| state.windows.get(&id).map(|w| (id, w))) {
        let flags = format!(
            "{}{}",
            if state.sessions[&w.session].active == id {
                "*"
            } else {
                ""
            },
            if w.zoom.is_some() { "Z" } else { "" }
        );
        match key {
            "window_id" => return format!("@{id}"),
            "window_name" => return w.name.clone(),
            "window_index" => return w.order.to_string(),
            "window_layout" => return state.layout(id, false),
            "window_visible_layout" => return state.layout(id, true),
            "window_flags" => return if flags.is_empty() { "-".into() } else { flags },
            "window_raw_flags" => return flags,
            "window_width" => return w.rect.cols.to_string(),
            "window_height" => return w.rect.rows.to_string(),
            "window_active" => return u8::from(s.is_some_and(|s| s.active == id)).to_string(),
            "history_limit" => return "2000".into(),
            _ => {}
        }
    }
    if let Some((id, p)) = pane.and_then(|id| state.panes.get(&id).map(|p| (id, p))) {
        match key {
            "pane_id" => return format!("%{id}"),
            "pane_width" => return p.rect.cols.to_string(),
            "pane_height" => return p.rect.rows.to_string(),
            "pane_left" => return p.rect.x.to_string(),
            "pane_top" => return p.rect.y.to_string(),
            "pane_index" => return "0".into(),
            "pane_title" => return p.title.clone(),
            "pane_current_path" => return p.terminal.cwd().to_string_lossy().into_owned(),
            "pane_current_command" => return p.terminal.foreground_command(),
            "pane_dead" => return u8::from(!p.terminal.is_running()).to_string(),
            "pane_pid" => return p.terminal.process_id().unwrap_or(0).to_string(),
            "pane_active" => {
                return u8::from(
                    state
                        .window_of(id)
                        .is_ok_and(|w| state.windows[&w].active == id),
                )
                .to_string()
            }
            "cursor_x" => return p.screen.cursor_position().1.to_string(),
            "cursor_y" => return p.screen.cursor_position().0.to_string(),
            "cursor_flag" => return u8::from(!p.screen.hide_cursor()).to_string(),
            "alternate_on" => return u8::from(p.screen.alternate_screen()).to_string(),
            "scroll_region_lower" => return p.rect.rows.saturating_sub(1).to_string(),
            "alternate_saved_x"
            | "alternate_saved_y"
            | "insert_flag"
            | "wrap_flag"
            | "keypad_flag"
            | "keypad_cursor_flag"
            | "origin_flag"
            | "focus_flag"
            | "bracketed_paste"
            | "scroll_region_upper"
            | "mouse_standard_flag"
            | "mouse_button_flag"
            | "mouse_any_flag"
            | "mouse_utf8_flag"
            | "mouse_sgr_flag"
            | "cursor_shape"
            | "cursor_blinking" => return "0".into(),
            _ => {}
        }
    }
    String::new()
}
