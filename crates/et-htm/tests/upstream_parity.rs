//! Expected values transcribed from canonical 8a306f6, not Rust internals.
use et_htm::{
    control::{execute, ClientFlags},
    framing,
    state::MultiplexerState,
};

fn run(state: &mut MultiplexerState, line: &str) -> String {
    let commands = framing::parse(line).unwrap();
    String::from_utf8(
        execute(state, &mut ClientFlags::default(), &commands[0])
            .unwrap_or_else(|e| panic!("{line}: {e}")),
    )
    .unwrap()
}

#[test]
fn canonical_frontend_noops_and_ignored_creation_operands() {
    let mut s = MultiplexerState::new().unwrap();
    for cmd in [
        "copy-mode -t %0",
        "list-keys",
        "lsk",
        "list-clients",
        "lsc",
        "phony-command",
        "clear-history -t %0",
        "clearhist",
        "link-window -s @0 -t $1",
        "linkw",
        "set -g status off",
        "show -gv status",
        "capture-pane -t %0",
        "refresh-client -B subscription -f unknown",
    ] {
        assert_eq!(run(&mut s, cmd), "", "{cmd}");
    }
    assert_eq!(
        run(
            &mut s,
            "new-window -adkP -t $99 -n named 'ignored shell operand'"
        ),
        "@1"
    );
    assert_eq!(run(&mut s, "split-window -bdfhvP -t %1 -l 3 ignored"), "%2");
    assert_eq!(
        run(&mut s, "display -p '#{pane_width} #{pane_height}'"),
        "80 11"
    );
    assert_eq!(run(&mut s, "display '#{pane_id}'"), "");
}

#[test]
fn canonical_nary_split_layouts_and_directional_resize() {
    let mut s = MultiplexerState::new().unwrap();
    run(&mut s, "splitw -h");
    run(&mut s, "resizep -t %1 -R 3");
    assert_eq!(
        run(&mut s, "display -p '#{window_layout}'"),
        "9fa5,80x24,0,0{43x24,0,0,0,36x24,44,0,1}"
    );
    run(&mut s, "splitw -h -t %0");
    assert_eq!(
        run(&mut s, "lsp -F '#{pane_id}:#{pane_width}:#{pane_left}'"),
        "%0:21:0\n%1:18:22\n%2:39:41\n"
    );
    run(&mut s, "select-layout even-vertical");
    assert_eq!(
        run(&mut s, "lsp -F '#{pane_id}:#{pane_height}:#{pane_top}'"),
        "%0:7:0\n%1:7:8\n%2:8:16\n"
    );
    run(&mut s, "selectl main-vertical");
    assert_eq!(run(&mut s, "lsp -F '#{pane_width}'"), "26\n26\n26\n");
}

#[test]
fn canonical_reparenting_preserves_shells_and_layout_order() {
    let mut s = MultiplexerState::new().unwrap();
    run(&mut s, "splitw -h");
    let pid = run(&mut s, "display -pt%0 '#{pane_pid}'");
    run(&mut s, "swapp -s %0 -t %1");
    assert_eq!(run(&mut s, "lsp -F '#{pane_id}'"), "%1\n%0\n");
    assert_eq!(run(&mut s, "breakp -s %0 -P"), "@1");
    run(&mut s, "joinp -s %0 -t %1 -hb");
    assert_eq!(run(&mut s, "lsp -t @0 -F '#{pane_id}'"), "%0\n%1\n");
    assert_eq!(run(&mut s, "display -pt%0 '#{pane_pid}'"), pid);
    run(&mut s, "new -d -s other");
    run(&mut s, "movew -s @0 -t other");
    assert_eq!(
        run(&mut s, "ls -F '#{session_id}:#{session_name}'"),
        "$2:other\n"
    );
    assert_eq!(run(&mut s, "lsw -F '#{window_id}'"), "@2\n@0\n");
    run(&mut s, "unlinkw -t @0");
    assert_eq!(run(&mut s, "lsp -a -F '#{pane_id}'"), "%2\n");
}

#[test]
fn canonical_absolute_resize_zoom_and_cross_window_last_pane_move() {
    let mut s = MultiplexerState::new().unwrap();
    run(&mut s, "refresh -C124x40");
    run(&mut s, "splitw -h");
    run(&mut s, "resizep -t%0 -x61 -y40");
    run(&mut s, "resizep -t%1 -x62 -y40");
    assert_eq!(
        run(&mut s, "lsp -F '#{pane_id}:#{pane_width}:#{pane_height}'"),
        "%0:61:40\n%1:62:40\n"
    );
    run(&mut s, "resizep -t%0 -x70");
    assert_eq!(run(&mut s, "lsp -F '#{pane_width}'"), "70\n53\n");
    let normal = run(&mut s, "display -p '#{window_layout}'");
    run(&mut s, "resizep -t%1 -Z");
    assert_eq!(run(&mut s, "display -p '#{window_flags}'"), "*Z");
    // Verified by the unmodified C++ oracle: dumpNode uses live pane
    // rectangles even for the non-visible layout while zoomed.
    assert_eq!(
        run(&mut s, "display -p '#{window_layout}'"),
        "e5ff,124x40,0,0{70x40,0,0,0,124x40,0,0,1}"
    );
    assert!(run(&mut s, "display -p '#{window_visible_layout}'").ends_with(",124x40,0,0,1"));
    run(&mut s, "resizep -t%1 -Z");
    assert_eq!(run(&mut s, "display -p '#{window_layout}'"), normal);
    assert_eq!(run(&mut s, "lsp -F '#{pane_width}'"), "70\n53\n");
    run(&mut s, "neww -n second");
    let pid = run(&mut s, "display -pt%2 '#{pane_pid}'");
    run(&mut s, "movep -s%2 -t%0 -hb");
    assert!(!s.windows.contains_key(&1));
    assert_eq!(run(&mut s, "lsp -F '#{pane_id}'"), "%2\n%0\n%1\n");
    assert_eq!(run(&mut s, "display -pt%2 '#{pane_pid}'"), pid);
}

#[test]
fn canonical_nested_formats_targets_and_option_scopes() {
    let mut s = MultiplexerState::new().unwrap();
    run(&mut s, "neww");
    assert_eq!(
        run(
            &mut s,
            "display -pt@0 '#{?window_active,yes,#{q:window_id}}'"
        ),
        "@0"
    );
    assert_eq!(
        run(
            &mut s,
            "display -p '#{?#{window_active},#{?pane_active,A,B},C}'"
        ),
        "A"
    );
    assert_eq!(
        run(&mut s, "display -p 'before#{unterminated'"),
        "before#{unterminated"
    );
    run(&mut s, "selectw -t htm:@0.0");
    assert_eq!(
        run(&mut s, "display -p '#{window_id}:#{pane_index}'"),
        "@0:0"
    );
    run(&mut s, "set -s @x server");
    run(&mut s, "set -g @x global");
    run(&mut s, "set @x session");
    run(&mut s, "setw -g @x window");
    assert_eq!(run(&mut s, "show -sv @x"), "server");
    assert_eq!(run(&mut s, "show -gv @x"), "global");
    assert_eq!(run(&mut s, "showw -gv @x"), "window");
    assert_eq!(run(&mut s, "display -p '#{@x}'"), "session");
    run(&mut s, "set -u @x");
    assert_eq!(run(&mut s, "show -v @x"), "");
}

#[test]
fn canonical_creation_and_close_notification_order() {
    let mut s = MultiplexerState::new().unwrap();
    run(&mut s, "neww");
    assert_eq!(
        s.notifications,
        b"%session-window-changed $1 @1\n%window-add @1\n"
    );
    s.notifications.clear();
    run(&mut s, "killw");
    assert_eq!(
        s.notifications,
        b"%session-window-changed $1 @0\n%unlinked-window-close @1\n"
    );
}

#[test]
fn canonical_attach_notifications_and_affinity_diagnostics() {
    let mut s = MultiplexerState::new().unwrap();
    s.attach_notifications();
    assert_eq!(
        s.notifications,
        b"%window-add @0\n%sessions-changed\n%session-changed $1 htm\n"
    );
    s.notifications.clear();
    s.attach_notifications();
    assert_eq!(s.notifications, b"%session-changed $1 htm\n");
    run(&mut s, "set @affinities '8,3;style=fs 2 7,x,4'");
    assert!(s.dump_panes().unwrap().starts_with("# affinities: [[2],[3,8],[4,7]]\n--- window @0 name=0 pane %0 active=1 80x24 cursor=0,0 shell_pid="));
    s.detach();
    run(&mut s, "set -u @affinities");
    assert!(s
        .dump_panes()
        .unwrap()
        .starts_with("# affinities: [[2],[3,8],[4,7]]\n"));
    run(&mut s, "set @affinities a_392c313b782030");
    assert!(s
        .dump_panes()
        .unwrap()
        .starts_with("# affinities: [[0],[1,9]]\n"));
    run(&mut s, "set @affinities a_zz");
    assert!(s.dump_panes().unwrap().starts_with("# affinities: []\n"));
}

#[test]
fn canonical_parser_escape_empty_and_unclosed_quote_behavior() {
    // An all-separator list falls back to the original command and errors;
    // unlike an empty argument vector, it must not detach the client.
    assert_eq!(framing::parse(";;").unwrap(), vec![vec![";;"]]);
    assert_eq!(
        framing::parse("display -p \\\\n").unwrap(),
        vec![vec!["display", "-p", "\\n"]]
    );
    assert_eq!(
        framing::parse("send -l '' \"\" 'open").unwrap(),
        vec![vec!["send", "-l", "open"]]
    );
    // The command-list pass unescapes once only when an unquoted separator
    // occurs; the argument pass then unescapes again, as in ControlMode.cpp.
    assert_eq!(
        framing::parse("setb a\\ b; display -p ok").unwrap(),
        vec![vec!["setb", "a", "b"], vec!["display", "-p", "ok"]]
    );
    let mut s = MultiplexerState::new().unwrap();
    run(&mut s, "setb -b -- -literal");
    assert_eq!(run(&mut s, "showb"), "-literal");
}

#[test]
fn canonical_capture_cell_serialization_and_legacy_title_filter() {
    let mut screen = et_htm::screen::PaneScreen::new(8, 1).unwrap();
    screen.process(b"\x1b[31mR\x1b[0m").unwrap();
    assert_eq!(
        screen
            .capture(&et_htm::screen::Capture {
                styled: true,
                ..Default::default()
            })
            .unwrap(),
        b"\x1b[0;31mR\x1b[0m\x1b[0m\n"
    );
    screen.process(b"\x1bkdiscard\x07X").unwrap();
    assert_eq!(screen.capture(&Default::default()).unwrap(), b"RX\n");
    screen.process(b"\x1b\x1bkdiscard\x1b\x1b\\Y").unwrap();
    // Native canonical oracle returns 52580a: the extra ESC reaches libvterm
    // and makes Y an escape final, rather than a printable cell.
    assert_eq!(screen.capture(&Default::default()).unwrap(), b"RX\n");
}

#[cfg(unix)]
#[test]
fn canonical_shell_environment_foreground_and_automatic_rename() {
    let mut s = MultiplexerState::new().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        s.poll(true, false, false);
        if !run(&mut s, "display -p '#{pane_current_command}'").is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let name = run(&mut s, "display -p '#{pane_current_command}'");
    assert!(!name.is_empty());
    assert_eq!(s.windows[&0].name, name);
    run(&mut s, "renamew fixed");
    s.poll(true, false, false);
    assert_eq!(s.windows[&0].name, "fixed");
    s.panes
        .get_mut(&0)
        .unwrap()
        .terminal
        .append_data(b"printf 'ENV_%s=%s/%s' CHECK \"$TERM\" \"$PROMPT_EOL_MARK\"\n")
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        s.poll(true, false, false);
        if run(&mut s, "capturep -p").contains("ENV_CHECK=screen/") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "shell environment mismatch"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
