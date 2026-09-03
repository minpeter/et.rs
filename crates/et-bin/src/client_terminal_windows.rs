//! Windows client terminal loop.
//!
//! Upstream's Windows client (`TerminalClient.cpp`, `#ifdef WIN32`) cannot
//! `select()` a console handle, so it peeks console input records and polls the
//! socket with a 10ms `select()` timeout. This loop keeps that structure using
//! crossterm for console events (which reads the same console input records)
//! and non-blocking socket reads.
//!
//! One deliberate improvement over upstream: upstream forwards only
//! `uChar.AsciiChar` from each key-down record, which silently drops arrows,
//! Home/End, and function keys. Those keys are translated into the ANSI
//! sequences a remote shell expects instead of being discarded.

use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEventKind};
use et_core::proto::TerminalPacketType;
use et_net::connection::Connection;
use et_net::forward::{is_forward_packet, Forwarder};

use crate::client_output::{ConsoleCompletion, GRACEFUL_DRAIN_STALL_TIMEOUT};
use crate::client_terminal::{
    classify_forward_completion, connection_ended, encoded_buffer, recover_transport,
    terminal_error, terminal_io, terminal_size_payload, terminal_text, write_owned_recovering,
    write_terminal_size_recovering, DisplayOutcome, OwnedWriteOutcome, RetainedCompletion,
    TerminalModeState,
};
use crate::error::ClientError;
use crate::initial_connect::ReconnectOutcome;

const MISSED_KEEPALIVES: u32 = 3;
/// Console/socket cadence, matching upstream's 10ms `select()` timeout.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

pub fn pump<F>(
    connection: &mut Connection,
    options: crate::client_terminal_loop::PumpOptions<'_>,
    forwarder: &mut Forwarder,
    mut reconnect: F,
) -> Result<(), ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    let crate::client_terminal_loop::PumpOptions {
        read_stdin,
        keepalive_seconds,
        flow_control,
        terminal_enabled,
        auto_cursor_report,
        terminal_modes,
    } = options;
    let console_output = crate::client_output::ConsoleOutput::stdout(flow_control)
        .map_err(|error| terminal_io("starting console output worker", error))?;
    let interval = Duration::from_secs(u64::from(keepalive_seconds.max(1)));
    let silence = interval.saturating_mul(MISSED_KEEPALIVES);
    let mut last_received = Instant::now();
    let mut next_keepalive = last_received + interval;
    if let Ok(path) = std::env::var("ET_SSH_READY") {
        let _ = std::fs::write(path, b"ready");
    }
    // A forwarding packet the worker had no room for. While it is held, no
    // further session packets are read so forwarding data stays ordered.
    let mut pending_forward: Option<et_core::packet::Packet> = None;
    let mut pending_output: Option<et_core::packet::Packet> = None;
    loop {
        console_output
            .check_error()
            .map_err(|error| terminal_io("writing terminal output", error))?;
        if auto_cursor_report {
            for _ in 0..console_output
                .take_cursor_reports()
                .map_err(|error| terminal_io("reading console confirmations", error))?
            {
                if matches!(
                    write_cursor_report(connection, &mut reconnect, terminal_enabled)?,
                    OwnedWriteOutcome::SessionEnded
                ) {
                    return finish_remote_completion(
                        console_output,
                        pending_output,
                        pending_forward,
                        terminal_enabled,
                        terminal_modes,
                        forwarder,
                        None,
                    );
                }
            }
        }
        let mut reconnect_needed = false;
        // Retry the held packet first: draining the forwarder's outbound
        // queue below is what frees worker capacity, so this makes progress
        // every 10ms tick instead of deadlocking on a blocking send.
        if let Some(packet) = pending_forward.take() {
            pending_forward = forwarder
                .try_receive(packet)
                .map_err(|error| terminal_text(error.to_string()))?;
        }
        if let Some(packet) = pending_output.take() {
            match route_server_packet(packet, terminal_enabled, terminal_modes, &console_output)? {
                DisplayOutcome::Displayed { cursor_report }
                    if cursor_report && auto_cursor_report && !console_output.is_async() =>
                {
                    if matches!(
                        write_cursor_report(connection, &mut reconnect, terminal_enabled)?,
                        OwnedWriteOutcome::SessionEnded
                    ) {
                        return finish_remote_completion(
                            console_output,
                            pending_output,
                            pending_forward,
                            terminal_enabled,
                            terminal_modes,
                            forwarder,
                            None,
                        );
                    }
                }
                DisplayOutcome::Displayed { .. } => {}
                DisplayOutcome::Pending(packet) => pending_output = Some(packet),
            }
        }

        // 1. Console input and resize notifications.
        if read_stdin {
            while crossterm::event::poll(Duration::from_millis(0))
                .map_err(|error| terminal_text(format!("polling console input: {error}")))?
            {
                let event = crossterm::event::read()
                    .map_err(|error| terminal_text(format!("reading console input: {error}")))?;
                match event {
                    Event::Key(key) => {
                        let bytes = key_bytes(&key);
                        if bytes.is_empty() {
                            continue;
                        }
                        let payload = encoded_buffer(&bytes);
                        match write_owned_recovering(
                            connection,
                            TerminalPacketType::TerminalBuffer as u8,
                            &payload,
                            &mut reconnect,
                            terminal_enabled,
                        )? {
                            OwnedWriteOutcome::Written => {}
                            OwnedWriteOutcome::Recovered => reconnect_needed = false,
                            OwnedWriteOutcome::SessionEnded => {
                                return finish_remote_completion(
                                    console_output,
                                    pending_output,
                                    pending_forward,
                                    terminal_enabled,
                                    terminal_modes,
                                    forwarder,
                                    None,
                                );
                            }
                        }
                    }
                    Event::Resize(_, _) if terminal_enabled => {
                        if let Some(payload) = terminal_size_payload()? {
                            match write_terminal_size_recovering(
                                connection,
                                &payload,
                                &mut reconnect,
                            )? {
                                OwnedWriteOutcome::Written => {}
                                OwnedWriteOutcome::Recovered => reconnect_needed = false,
                                OwnedWriteOutcome::SessionEnded => {
                                    return finish_remote_completion(
                                        console_output,
                                        pending_output,
                                        pending_forward,
                                        terminal_enabled,
                                        terminal_modes,
                                        forwarder,
                                        None,
                                    );
                                }
                            }
                        }
                    }
                    // Upstream forwards neither mouse nor focus records.
                    Event::Mouse(mouse) if matches!(mouse.kind, MouseEventKind::Moved) => {}
                    _ => {}
                }
            }
        }

        // 2. Server packets.
        while pending_forward.is_none() && pending_output.is_none() {
            match connection.try_read_packet() {
                Ok(Some(packet)) => {
                    last_received = Instant::now();
                    if packet.header() == TerminalPacketType::KeepAlive as u8 {
                        if let Some(ack) = et_core::keepalive::decode_ack(packet.payload()) {
                            connection.acknowledge_delivery(ack);
                        }
                    }
                    if is_forward_packet(packet.header()) {
                        pending_forward = forwarder
                            .try_receive(packet)
                            .map_err(|error| terminal_text(error.to_string()))?;
                    } else {
                        match route_server_packet(
                            packet,
                            terminal_enabled,
                            terminal_modes,
                            &console_output,
                        )? {
                            DisplayOutcome::Displayed { cursor_report }
                                if cursor_report
                                    && auto_cursor_report
                                    && !console_output.is_async() =>
                            {
                                if matches!(
                                    write_cursor_report(
                                        connection,
                                        &mut reconnect,
                                        terminal_enabled,
                                    )?,
                                    OwnedWriteOutcome::SessionEnded
                                ) {
                                    return finish_remote_completion(
                                        console_output,
                                        pending_output,
                                        pending_forward,
                                        terminal_enabled,
                                        terminal_modes,
                                        forwarder,
                                        None,
                                    );
                                }
                            }
                            DisplayOutcome::Displayed { .. } => {}
                            DisplayOutcome::Pending(packet) => pending_output = Some(packet),
                        }
                    }
                }
                Ok(None) => break,
                Err(error) if connection_ended(&error) => {
                    reconnect_needed = true;
                    break;
                }
                Err(error) => return Err(terminal_error(error)),
            }
        }

        // 3. Outbound forwarding packets.
        while let Some(packet) = forwarder
            .try_outbound()
            .map_err(|error| terminal_text(error.to_string()))?
        {
            match write_owned_recovering(
                connection,
                packet.header(),
                packet.payload(),
                &mut reconnect,
                terminal_enabled,
            )? {
                OwnedWriteOutcome::Written => {}
                OwnedWriteOutcome::Recovered => reconnect_needed = false,
                OwnedWriteOutcome::SessionEnded => {
                    return finish_remote_completion(
                        console_output,
                        pending_output,
                        pending_forward,
                        terminal_enabled,
                        terminal_modes,
                        forwarder,
                        Some(packet),
                    );
                }
            }
        }

        let now = Instant::now();
        if pending_output.is_none() && now.saturating_duration_since(last_received) >= silence {
            reconnect_needed = true;
        }
        if reconnect_needed {
            if !recover_transport(connection, &mut reconnect, terminal_enabled)? {
                return finish_remote_completion(
                    console_output,
                    pending_output,
                    pending_forward,
                    terminal_enabled,
                    terminal_modes,
                    forwarder,
                    None,
                );
            }
            last_received = Instant::now();
            next_keepalive = last_received + interval;
            continue;
        }
        if Instant::now() >= next_keepalive {
            // The payload acknowledges everything read so far, so the server
            // can trim its replay backup; legacy servers ignore it.
            let ack = connection.keepalive_ack();
            if matches!(
                write_owned_recovering(
                    connection,
                    TerminalPacketType::KeepAlive as u8,
                    &ack,
                    &mut reconnect,
                    terminal_enabled,
                )?,
                OwnedWriteOutcome::SessionEnded
            ) {
                return finish_remote_completion(
                    console_output,
                    pending_output,
                    pending_forward,
                    terminal_enabled,
                    terminal_modes,
                    forwarder,
                    None,
                );
            }
            next_keepalive = Instant::now() + interval;
        }

        // 4. Idle wait. Console events wake this immediately; socket data is
        // observed on the next tick, exactly like upstream's select() timeout.
        if read_stdin {
            let _ = crossterm::event::poll(POLL_INTERVAL);
        } else {
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

fn finish_remote_completion(
    mut output: crate::client_output::ConsoleOutput,
    pending_output: Option<et_core::packet::Packet>,
    pending_forward: Option<et_core::packet::Packet>,
    terminal_enabled: bool,
    terminal_modes: &mut TerminalModeState,
    forwarder: &mut Forwarder,
    current_outbound: Option<et_core::packet::Packet>,
) -> Result<(), ClientError> {
    let mut retained = RetainedCompletion::new(pending_output, pending_forward);
    let mut output_progress = output
        .worker_progress()
        .map_err(|error| terminal_io("tracking retained terminal output", error))?;
    let mut output_deadline = Instant::now() + GRACEFUL_DRAIN_STALL_TIMEOUT;
    loop {
        output
            .check_error()
            .map_err(|error| terminal_io("writing retained terminal output", error))?;
        if retained.advance(
            |packet| match route_server_packet(packet, terminal_enabled, terminal_modes, &output)? {
                DisplayOutcome::Displayed { .. } => Ok(None),
                DisplayOutcome::Pending(packet) => Ok(Some(packet)),
            },
            |packet| {
                forwarder
                    .try_receive(packet)
                    .map_err(|error| terminal_text(error.to_string()))
            },
        )? {
            let abandoned = forwarder
                .shutdown_hard()
                .map_err(|error| terminal_text(error.to_string()))?;
            classify_forward_completion(current_outbound, abandoned)?;
            return output
                .complete(ConsoleCompletion::RemoteSessionEnded)
                .map_err(|error| terminal_io("draining terminal output", error));
        }
        if retained.terminal_pending() {
            let progress = output
                .worker_progress()
                .map_err(|error| terminal_io("tracking retained terminal output", error))?;
            if progress != output_progress {
                output_progress = progress;
                output_deadline = Instant::now() + GRACEFUL_DRAIN_STALL_TIMEOUT;
            } else if Instant::now() >= output_deadline {
                let abandoned = forwarder
                    .shutdown_hard()
                    .map_err(|error| terminal_text(error.to_string()))?;
                classify_forward_completion(current_outbound, abandoned)?;
                return output
                    .finish_gracefully_after_stall()
                    .map_err(|error| terminal_io("cancelling stalled terminal output", error));
            }
        }
        if let Some(packet) = forwarder
            .try_outbound()
            .map_err(|error| terminal_text(error.to_string()))?
        {
            let abandoned = forwarder
                .shutdown_hard()
                .map_err(|error| terminal_text(error.to_string()))?;
            classify_forward_completion(Some(packet), abandoned)?;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn write_cursor_report<F>(
    connection: &mut Connection,
    reconnect: &mut F,
    send_terminal_size: bool,
) -> Result<OwnedWriteOutcome, ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    let payload = encoded_buffer(crate::client_terminal::CURSOR_REPORT_REPLY);
    write_owned_recovering(
        connection,
        TerminalPacketType::TerminalBuffer as u8,
        &payload,
        reconnect,
        send_terminal_size,
    )
}

/// Returns `true` when a cursor position report must be sent back.
fn route_server_packet(
    packet: et_core::packet::Packet,
    terminal_enabled: bool,
    terminal_modes: &mut TerminalModeState,
    output: &crate::client_output::ConsoleOutput,
) -> Result<DisplayOutcome, ClientError> {
    if terminal_enabled || packet.header() == TerminalPacketType::KeepAlive as u8 {
        return crate::client_terminal::display_packet_with(packet, |bytes| {
            output
                .try_write(bytes, terminal_modes)
                .map_err(|error| terminal_io("writing terminal output", error))
        });
    }
    if packet.header() == TerminalPacketType::TerminalBuffer as u8 {
        return Ok(DisplayOutcome::Displayed {
            cursor_report: false,
        });
    }
    Err(terminal_text(
        "server sent an unsupported no-terminal packet",
    ))
}

/// Translate a console key event into the bytes a remote PTY expects.
pub(crate) fn key_bytes(key: &KeyEvent) -> Vec<u8> {
    // Upstream reacts to key-down records only.
    if matches!(key.kind, KeyEventKind::Release) {
        return Vec::new();
    }
    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let mut bytes = Vec::new();
    match key.code {
        KeyCode::Char(character) => {
            if control {
                // Ctrl+<key> maps to the matching C0 control byte.
                let control_byte = match character {
                    ' ' => Some(0),
                    '@'..='_' => Some(character as u8 & 0x1f),
                    'a'..='z' => Some(character.to_ascii_uppercase() as u8 & 0x1f),
                    '?' => Some(0x7f),
                    _ => None,
                };
                match control_byte {
                    Some(byte) => bytes.push(byte),
                    None => bytes.extend_from_slice(character.to_string().as_bytes()),
                }
            } else {
                bytes.extend_from_slice(character.to_string().as_bytes());
            }
        }
        KeyCode::Enter => bytes.push(b'\r'),
        KeyCode::Tab => bytes.push(b'\t'),
        KeyCode::BackTab => bytes.extend_from_slice(b"\x1b[Z"),
        KeyCode::Backspace => bytes.push(0x7f),
        KeyCode::Esc => bytes.push(0x1b),
        KeyCode::Up => bytes.extend_from_slice(b"\x1b[A"),
        KeyCode::Down => bytes.extend_from_slice(b"\x1b[B"),
        KeyCode::Right => bytes.extend_from_slice(b"\x1b[C"),
        KeyCode::Left => bytes.extend_from_slice(b"\x1b[D"),
        KeyCode::Home => bytes.extend_from_slice(b"\x1b[H"),
        KeyCode::End => bytes.extend_from_slice(b"\x1b[F"),
        KeyCode::PageUp => bytes.extend_from_slice(b"\x1b[5~"),
        KeyCode::PageDown => bytes.extend_from_slice(b"\x1b[6~"),
        KeyCode::Insert => bytes.extend_from_slice(b"\x1b[2~"),
        KeyCode::Delete => bytes.extend_from_slice(b"\x1b[3~"),
        KeyCode::F(number @ 1..=4) => {
            bytes.extend_from_slice(&[0x1b, b'O', b'P' + (number - 1)]);
        }
        KeyCode::F(number @ 5..=12) => {
            const CODES: [&[u8]; 8] = [b"15", b"17", b"18", b"19", b"20", b"21", b"23", b"24"];
            bytes.extend_from_slice(b"\x1b[");
            bytes.extend_from_slice(CODES[usize::from(number) - 5]);
            bytes.push(b'~');
        }
        _ => {}
    }
    if alt && !bytes.is_empty() {
        // Alt is sent as an ESC prefix, like a Unix terminal.
        let mut prefixed = Vec::with_capacity(bytes.len() + 1);
        prefixed.push(0x1b);
        prefixed.extend_from_slice(&bytes);
        return prefixed;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventState;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn plain_characters_and_control_bytes_match_a_unix_terminal() {
        assert_eq!(
            key_bytes(&key(KeyCode::Char('a'), KeyModifiers::NONE)),
            b"a"
        );
        assert_eq!(
            key_bytes(&key(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            vec![0x03]
        );
        assert_eq!(
            key_bytes(&key(KeyCode::Char('d'), KeyModifiers::CONTROL)),
            vec![0x04]
        );
        assert_eq!(
            key_bytes(&key(KeyCode::Char(' '), KeyModifiers::CONTROL)),
            vec![0x00]
        );
        assert_eq!(key_bytes(&key(KeyCode::Enter, KeyModifiers::NONE)), b"\r");
        assert_eq!(
            key_bytes(&key(KeyCode::Backspace, KeyModifiers::NONE)),
            vec![0x7f]
        );
    }

    #[test]
    fn navigation_keys_become_ansi_sequences() {
        assert_eq!(key_bytes(&key(KeyCode::Up, KeyModifiers::NONE)), b"\x1b[A");
        assert_eq!(
            key_bytes(&key(KeyCode::Left, KeyModifiers::NONE)),
            b"\x1b[D"
        );
        assert_eq!(
            key_bytes(&key(KeyCode::Delete, KeyModifiers::NONE)),
            b"\x1b[3~"
        );
        assert_eq!(
            key_bytes(&key(KeyCode::F(1), KeyModifiers::NONE)),
            b"\x1bOP"
        );
        assert_eq!(
            key_bytes(&key(KeyCode::F(5), KeyModifiers::NONE)),
            b"\x1b[15~"
        );
    }

    #[test]
    fn alt_prefixes_escape_and_release_events_are_ignored() {
        assert_eq!(
            key_bytes(&key(KeyCode::Char('b'), KeyModifiers::ALT)),
            vec![0x1b, b'b']
        );
        let mut release = key(KeyCode::Char('a'), KeyModifiers::NONE);
        release.kind = KeyEventKind::Release;
        assert!(key_bytes(&release).is_empty());
    }

    #[test]
    fn multibyte_characters_are_sent_as_utf8() {
        assert_eq!(
            key_bytes(&key(KeyCode::Char('한'), KeyModifiers::NONE)),
            "한".as_bytes()
        );
    }
}
