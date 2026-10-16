---
packages:
  et:
    type: patch
---

## Switch wire crypto to libsodium and collapse forwarding onto one poll loop

- The wire cipher (XSalsa20-Poly1305, EternalTerminal's `crypto_secretbox`
  scheme) now runs through libsodium via the new `et-sodium` crate, the
  workspace's single FFI boundary. Nonce scheme, packet layout, and the
  `fixtures/wire.json` byte oracles are unchanged. Building now also needs a C
  toolchain, because the bundled libsodium is compiled from source.
- A session reset rekeys from the original passkey on every reset. The first
  libsodium port derived each epoch from the previous epoch's key, so the
  second and later reattach of a named session failed the recovery handshake
  with a poly1305 verification error (`client is ahead of server`).
- On Unix the forwarding worker polls every forwarded socket itself instead of
  running a reader/writer thread pair per socket, matching upstream
  `PortForwardHandler::update`. Reads, writes, half-closes, and window credit
  are handled inline, so a saturated worker no longer pays a context switch per
  packet per hop. Windows keeps the threaded model.
- Coalesce forwarding worker wakeups and outbound notifications under bulk
  transfer, flush queued socket writes and flow-control credits in the same
  poll cycle, and raise the flow-control socket send buffer from 32 KiB to
  256 KiB so full forwarding frames do not block session write batches on
  every packet.
