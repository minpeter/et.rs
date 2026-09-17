//! Canonical ControlCommands + MultiplexerState distinguish parsing from lookup.
use et_htm::{
    control::{execute, ClientFlags},
    framing,
    state::MultiplexerState,
};

fn command(state: &mut MultiplexerState, line: &str) -> Result<Vec<u8>, String> {
    execute(
        state,
        &mut ClientFlags::default(),
        &framing::parse(line)?[0],
    )
}

#[test]
fn missing_ids_are_command_specific_not_a_global_rejection() {
    let mut s = MultiplexerState::new().unwrap();
    for line in [
        "killp -t%999",
        "killw -t@999",
        "unlinkw -t@999",
        "kill-session -t$999",
        "swapp -s%999 -t%0",
        "movep -s%0 -t%999",
        "joinp -s%999 -t%999",
        "movew -s@999 -t$1",
        "movew -s@0 -t$999",
        "capturep -pt%999",
        "set -pt%999 @x ignored",
        "show -pt%999 @x",
        "setw -t@999 @x ignored",
        "showw -t@999 @x",
        "set -t$999 @x ignored",
        "show -t$999 @x",
    ] {
        assert_eq!(
            command(&mut s, line).unwrap_or_else(|e| panic!("{line}: {e}")),
            b"",
            "{line}"
        );
    }
    assert_eq!(s.panes.len(), 1);
    assert!(s.options.is_empty());
    for target in ["%999", "@999", "$999"] {
        assert_eq!(
            command(
                &mut s,
                &format!("display -pt{target} '#{{pane_id}}:#{{window_id}}:#{{session_id}}'")
            )
            .unwrap(),
            b"%0:@0:$1"
        );
    }
    for target in ["%999", "@999"] {
        assert_eq!(
            command(&mut s, &format!("lsp -t{target} -F '#{{pane_id}}'")).unwrap(),
            b"%0\n"
        );
    }
    assert_eq!(command(&mut s, "breakp -s%999 -P").unwrap(), b"@0");
    for line in [
        "selectp -t%999",
        "selectw -t@999",
        "splitw -t%999",
        "send -t%999 x",
        "resizep -t%999 -R",
        "resizew -t@999",
        "renamew -t@999 name",
        "selectl -t@999 tiled",
        "lsw -t$999",
        "attach -t$999",
        "rename -t$999 name",
        "capturep -pt@999",
    ] {
        assert!(command(&mut s, line).is_err(), "{line}");
    }
    assert_eq!(
        command(&mut s, "display -pt%+0suffix '#{pane_id}'").unwrap(),
        b"%0"
    );
    assert!(command(&mut s, "lsp -a -t%invalid").is_err());
    assert_eq!(command(&mut s, "resizep -t%999").unwrap(), b"");
    assert_eq!(
        command(&mut s, "refresh -A%1:off -A%999:continue").unwrap(),
        b""
    );
    assert!(String::from_utf8_lossy(&s.notifications).contains("%continue %999\n"));
    assert_eq!(command(&mut s, "splitw -P").unwrap(), b"%1");
    // The gate is registered before pane creation, not attached to a Pane.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let output = s.poll(false, false, false);
        assert!(!String::from_utf8_lossy(&output).contains("%output %1 "));
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    command(&mut s, "refresh -A%2:off").unwrap();
    s.close(1).unwrap();
    assert!(!s.pane_gates.contains_key(&1));
    assert!(s.pane_gates.contains_key(&2));
    assert_eq!(command(&mut s, "neww -P").unwrap(), b"@1");
    assert!(s.pane_gates.contains_key(&2));
    s.close_window(1);
    assert!(!s.pane_gates.contains_key(&2));
}
