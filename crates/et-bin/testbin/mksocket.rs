//! Binds a UNIX socket at the given path so the fake `ssh` in the bootstrap
//! tests creates the same object type real `ssh -MNf` does. A regular file is
//! refused by the client's socket validation, which would make every later
//! session fall back and stop exercising multiplexing.

fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: mksocket <path>");
        std::process::exit(2);
    };

    #[cfg(unix)]
    {
        let listener = match std::os::unix::net::UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("mksocket: bind failed: {error}");
                std::process::exit(1);
            }
        };
        // The socket file must outlive this process, like a real master's does.
        std::mem::forget(listener);
    }

    #[cfg(not(unix))]
    {
        if let Err(error) = std::fs::write(&path, []) {
            eprintln!("mksocket: write failed: {error}");
            std::process::exit(1);
        }
    }
}
