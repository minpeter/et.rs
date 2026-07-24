use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;

use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::initial_connect::Endpoint;

const MAX_RESOLVED_ADDRESSES: usize = 16;

pub trait EndpointResolver {
    fn resolve(
        &self,
        endpoint: &Endpoint,
        deadline: Deadline,
    ) -> Result<Vec<SocketAddr>, ClientError>;
}

#[derive(Debug, Default)]
pub struct SystemResolver;

impl EndpointResolver for SystemResolver {
    fn resolve(
        &self,
        endpoint: &Endpoint,
        deadline: Deadline,
    ) -> Result<Vec<SocketAddr>, ClientError> {
        if let Ok(address) = endpoint.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(address, endpoint.port)]);
        }
        let display = endpoint.to_string();
        let host = endpoint.host.clone();
        let port = endpoint.port;
        resolve_operation(display, deadline, move || {
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.take(MAX_RESOLVED_ADDRESSES).collect())
        })
    }
}

fn resolve_operation<F>(
    endpoint: String,
    deadline: Deadline,
    operation: F,
) -> Result<Vec<SocketAddr>, ClientError>
where
    F: FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
{
    let remaining = deadline
        .remaining()
        .ok_or_else(|| ClientError::DnsTimeout(endpoint.clone()))?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("et-dns".to_string())
        .spawn(move || {
            let _ = sender.send(operation());
        })
        .map_err(ClientError::DnsWorker)?;
    match receiver.recv_timeout(remaining) {
        Ok(result) => {
            if worker.join().is_err() {
                return Err(ClientError::DnsWorkerPanicked);
            }
            result.map_err(|source| ClientError::UnreachableEndpoint { endpoint, source })
        }
        Err(RecvTimeoutError::Timeout) => {
            // getaddrinfo is not cancellable. This detached worker owns no
            // application state and exits when that outstanding call returns.
            drop(worker);
            Err(ClientError::DnsTimeout(endpoint))
        }
        Err(RecvTimeoutError::Disconnected) => {
            let panicked = worker.join().is_err();
            if panicked {
                Err(ClientError::DnsWorkerPanicked)
            } else {
                Err(ClientError::UnreachableEndpoint {
                    endpoint,
                    source: io::Error::other("DNS resolver returned no result"),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn dns_operation_obeys_deadline_without_polling() {
        let (release_sender, release_receiver) = mpsc::channel();
        let (done_sender, done_receiver) = mpsc::sync_channel(1);
        let result = resolve_operation(
            "blocked.invalid:2022".to_string(),
            Deadline::after(Duration::from_millis(20)),
            move || {
                release_receiver.recv().map_err(io::Error::other)?;
                done_sender.send(()).map_err(io::Error::other)?;
                Ok(Vec::new())
            },
        );
        assert!(matches!(result, Err(ClientError::DnsTimeout(_))));
        release_sender.send(()).unwrap();
        done_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
    }
}
