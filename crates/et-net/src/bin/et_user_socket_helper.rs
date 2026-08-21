#![forbid(unsafe_code)]

fn main() {
    #[cfg(unix)]
    std::process::exit(et_net::user_socket_ops::run_helper());
    #[cfg(not(unix))]
    {
        eprintln!("et-user-socket-helper is Unix-only");
        std::process::exit(2);
    }
}
