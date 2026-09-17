//! Differential checks against unmodified canonical C++, not adapter-derived values.
use et_htm::screen::{Capture, PaneScreen};
use std::io::Write;
use std::process::{Command, Stdio};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore = "build tests/screen-oracle first and set HTM_SCREEN_ORACLE"]
fn libvterm_capture_differential() {
    let path = std::env::var_os("HTM_SCREEN_ORACLE").expect("HTM_SCREEN_ORACLE");
    let mut native = Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut transcript = String::from("13 5\n");
    let mut screen = PaneScreen::new(13, 5).unwrap();
    let mut actual = String::new();
    let chunks: &[&[u8]] = &[
        b"alpha\r\nbeta\r\ngamma\r\ndelta\r\nepsilon\r\nzeta",
        b"\x1b[2;4H@\x1b[K\x1b[1;4;3;7;31;104mRED\x1b[0m",
        "\r\n한글 e\u{301} 😀".as_bytes(),
        b"\x1b[38;5;201mINDEX\x1b[38;2;20;40;60mRGB\x1b[0m",
        b"\x1b[?1049hALT\r\n\x1b[?25lhidden",
        b"\x1b[?1049l\x1b[?25h",
        b"\x1b[2;4r\x1b[4;1H\r\nSCROLL\r\nMORE\x1b[r",
        b"\x1bkdiscard",
        b"\x1b",
        b"\\visible\x1bkdiscard\x07BEL",
        b"\x1b\x1bkdiscard\x1b\x1b\\Y",
        b"\x1b[3J\x1b[2J\x1b[Hclear",
        b"\x1b[2@ins\x1b[2P\x1b[2X",
        b"\x1b[4hINSERT\x1b[4l\r\n12345678901234567890123456789",
    ];
    for (index, chunk) in chunks.iter().enumerate() {
        transcript += &format!("feed {}\n", hex(chunk));
        screen.process(chunk).unwrap();
        if index == 5 || index == 12 {
            let (cols, rows) = if index == 5 { (9, 3) } else { (17, 7) };
            transcript += &format!("resize {cols} {rows}\n");
            screen.resize(cols, rows).unwrap();
        }
        for flags in 0..16 {
            for (start, end) in [(0, 0), (-8, -1), (1, 2)] {
                transcript += &format!("capture {flags} {start} {end}\n");
                actual += &hex(&screen
                    .capture(&Capture {
                        styled: flags & 1 != 0,
                        alternate: flags & 2 != 0,
                        join: flags & 4 != 0,
                        trailing: flags & 8 != 0,
                        start,
                        end,
                    })
                    .unwrap());
                actual.push('\n');
            }
        }
    }
    let mut stdin = native.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(transcript.as_bytes()).unwrap());
    let output = native.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(output.status.success());
    let expected = String::from_utf8(output.stdout).unwrap();
    assert_eq!(actual.lines().count(), expected.lines().count());
    for (i, (actual, expected)) in actual.lines().zip(expected.lines()).enumerate() {
        assert_eq!(actual, expected, "capture {i}");
    }
}
