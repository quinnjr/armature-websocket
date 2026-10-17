# Changelog — `armature-websocket`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Security

- Upgrade requests are authorized before the handshake completes (Cross-Site WebSocket Hijacking): every request passes an `OriginPolicy` (default rejects any request carrying an `Origin` header until origins are allowlisted; requests without `Origin` — non-browser clients — go on to the authorizer) and then a `HandshakeAuthorizer`, whose `Principal` is attached to the connection. Refused upgrades get a plain `401`/`403` response.
- The server binds `127.0.0.1:9001` by default instead of `0.0.0.0:9001`.
- The upgrade handshake is bounded by `handshake_timeout` (default 10 s), so silent pre-handshake sockets no longer hold a task forever.
- Concurrent connections are capped by `max_connections` (default 10 000); excess TCP connections are dropped at accept.
- Each connection's outbound queue is bounded (`outbound_queue_capacity`, default 1024 messages). A peer that stops reading is evicted (`WebSocketError::SlowConsumer`) instead of buffering without limit, and room broadcasts never block on or grow memory for a slow member. Teardown waits at most `close_timeout` (default 5 s) for the Close frame before aborting the writer.
- `max_frame_size` (default 64 KiB) and `max_write_buffer_size` (default 4 MiB; tungstenite's default was unbounded) are now set explicitly on every connection.
- `WebSocketClient`'s inbound queue is bounded (`inbound_queue_capacity`, default 1024 messages). When it is full the reader stops reading the socket until the application calls `recv`, so a flooding server is throttled by TCP backpressure instead of growing client memory without limit; no message is dropped.
- `Principal`'s `Debug` redacts attribute values; `WebSocketClientBuilder`'s `Debug` redacts URL userinfo and query string.

### Added

- `HandshakeAuthorizer` trait (implemented for `Fn(&HandshakeRequest) -> Result<Principal, HandshakeRejection>` closures), `AllowAnonymous`, `Principal`, `HandshakeRejection`, `HandshakeRequest`, `OriginPolicy`.
- `WebSocketServerConfig` fields and builder methods: `max_frame_size`, `max_write_buffer_size`, `outbound_queue_capacity`, `max_connections`, `handshake_timeout`, `close_timeout`, `origin_policy` (`allowed_origins(..)` shorthand), `authorizer(..)`, `allow_anonymous()`.
- `Connection::principal()`; `WebSocketError::SlowConsumer`.
- `WebSocketClientBuilder::inbound_queue_capacity` (must be non-zero; `connect` errors otherwise).

### Changed

- **Breaking:** `WebSocketServerBuilder::build` returns `WebSocketResult<WebSocketServer<H>>` and fails unless `.authorizer(..)` or `.allow_anonymous()` was called. Migration: add `.allow_anonymous()` (or a real authorizer) and `?` the result.
- **Breaking:** `WebSocketServer::new(config, handler)` is now `WebSocketServer::new(config, handler, authorizer) -> WebSocketResult<Self>`. Migration: pass `AllowAnonymous` or your authorizer and handle the `Result`.
- **Breaking:** `WebSocketHandler::on_connect`, `on_message` and `on_disconnect` take a `&Principal` after `connection_id`. Migration: add a `principal: &Principal` (or `_principal`) parameter.
- **Breaking:** the default `bind_addr` is loopback and browser origins are rejected by default. Migration: set `.bind_addr(..)` to expose the server and `.allowed_origins([..])` for browser clients.
- **Breaking:** `Connection::send` (and therefore broadcasts) no longer queue without limit; it returns `WebSocketError::SlowConsumer` and evicts the connection when its queue is full.

## [0.4.0] - 2026-09-15

### Changed

- **Breaking:** `tungstenite` (0.29 → 0.30) is a public dependency — `RawMessage`, `CloseFrame` and the `tungstenite::Message` conversions are part of this crate's API — so the upgrade is breaking and the minor moves.

### Security

- Require `rustls` 0.23.45 or later, which fixes RUSTSEC-2026-0285 (TLS 1.3 handshake messages accepted across encryption-level boundaries).

## [0.3.1] - 2026-08-04

### Fixed

- Requirements on sibling armature crates name a minor instead of `0`. Under
  Cargo's 0.x rules `version = "0"` matches any release ever made, and edition
  2024 selects the MSRV-aware resolver, so a consumer declaring an older
  `rust-version` was handed the oldest version satisfying it — resolving
  `armature-core = "0"` on Rust 1.89 produced `armature-core 0.2.3` while an
  explicit `armature-core = "0.8"` elsewhere in the same graph pulled 0.8.2.
  Two copies of core, and a build failing on symbols the older one lacks. Each
  0.x minor in this family is a breaking change, so the requirement now names
  one. No API change.
