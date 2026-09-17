//! Unmodified canonical dispatcher/state is the expected-value generator.
//! Only timestamps/sequences and C++ exception text are normalized. Replies,
//! errors, topology, formats, checked layouts and notification order are not.
use et_htm::{
    control::{execute, ClientFlags},
    framing,
    state::MultiplexerState,
};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn normalize(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    let mut body = Vec::new();
    let mut in_reply = false;
    for line in text.lines() {
        if line.starts_with("%begin ") {
            in_reply = true;
            out.push(format!(
                "%begin {}",
                line.split_whitespace().last().unwrap()
            ));
        } else if line.starts_with("%end ") || line.starts_with("%error ") {
            if line.starts_with("%end ") {
                out.append(&mut body);
            } else {
                body.clear();
            }
            out.push(format!(
                "{} {}",
                line.split_whitespace().next().unwrap(),
                line.split_whitespace().last().unwrap()
            ));
            in_reply = false;
        } else if in_reply {
            body.push(line.to_owned());
        } else {
            out.push(line.to_owned());
        }
    }
    assert!(!in_reply);
    out
}

#[test]
fn canonical_command_transcripts() {
    let corpus = include_str!("control-oracle/commands.txt");
    let commands: Vec<_> = corpus
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let expected = if let Some(path) = std::env::var_os("HTM_CONTROL_ORACLE") {
        let mut native = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = native.stdin.take().unwrap();
        let input = commands.join("\n") + "\n";
        let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
        let result = native.wait_with_output().unwrap();
        writer.join().unwrap();
        assert!(result.status.success());
        String::from_utf8(result.stdout).unwrap()
    } else {
        include_str!("control-oracle/commands.hex").to_owned()
    };
    assert_eq!(expected.lines().count(), commands.len());
    let mut state = MultiplexerState::new().unwrap();
    let mut flags = ClientFlags::default();
    for (line, hex) in commands.iter().zip(expected.lines()) {
        let expected: Vec<_> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        if line.starts_with("oracle-keys ") {
            let words = &framing::parse(line).unwrap()[0];
            assert_eq!(
                et_htm::control::encode_keys(&words[2..], words[1] == "hex", words[1] == "literal"),
                expected,
                "{line}"
            );
            continue;
        }
        let mut actual = Vec::new();
        for mut words in framing::parse(line).unwrap() {
            // The native oracle stubs PTY/cwd. Keep this structural corpus
            // runnable on Windows; real cwd behavior is tested separately.
            for word in &mut words {
                if word == "/tmp" {
                    *word = std::env::temp_dir().to_string_lossy().into_owned();
                }
            }
            if words
                .first()
                .is_some_and(|s| matches!(s.as_str(), "detach" | "detach-client" | "exit"))
            {
                state.detach();
                break;
            }
            let body = execute(&mut state, &mut flags, &words);
            let failed = body.is_err();
            actual.extend(framing::reply(1, 1, body));
            actual.append(&mut state.notifications);
            if failed {
                break;
            }
        }
        assert_eq!(normalize(&actual), normalize(&expected), "command: {line}");
    }
}
