//! # Armature WebSocket
//!
//! WebSocket server and client support for the Armature framework using tokio-tungstenite.
//!
//! ## Features
//!
//! - WebSocket server with connection management
//! - WebSocket client for outbound connections
//! - Room-based message broadcasting
//! - Connection state management
//! - Heartbeat/ping-pong support
//! - JSON message serialization
//!
//! ## Example
//!
//! ```rust,no_run
//! use armature_websocket::{
//!     HandshakeRejection, HandshakeRequest, Message, Principal, WebSocketHandler,
//!     WebSocketServerBuilder,
//! };
//! use async_trait::async_trait;
//!
//! struct ChatHandler;
//!
//! #[async_trait]
//! impl WebSocketHandler for ChatHandler {
//!     async fn on_connect(&self, connection_id: &str, principal: &Principal) {
//!         println!("{:?} connected as {}", principal.subject(), connection_id);
//!     }
//!
//!     async fn on_message(&self, connection_id: &str, _principal: &Principal, message: Message) {
//!         println!("Received from {}: {:?}", connection_id, message);
//!     }
//!
//!     async fn on_disconnect(&self, connection_id: &str, _principal: &Principal) {
//!         println!("Client disconnected: {}", connection_id);
//!     }
//! }
//!
//! # async fn run() -> armature_websocket::WebSocketResult<()> {
//! // Loopback by default; only browser pages served from the allowed origin
//! // may connect, and every upgrade must carry a valid bearer token.
//! let server = WebSocketServerBuilder::new()
//!     .allowed_origins(["https://chat.example.com"])
//!     .authorizer(|req: &HandshakeRequest| {
//!         match req.headers().get("authorization").and_then(|v| v.to_str().ok()) {
//!             Some("Bearer s3cret") => Ok(Principal::new("alice")),
//!             _ => Err(HandshakeRejection::unauthorized()),
//!         }
//!     })
//!     .build(ChatHandler)?;
//! server.run().await
//! # }
//! ```
//!
//! ## Security defaults
//!
//! - Binds `127.0.0.1:9001`; exposing the server is an explicit `bind_addr`.
//! - Every upgrade passes an [`OriginPolicy`] (default: reject any request
//!   that carries an `Origin` header, i.e. every browser page, until origins
//!   are allowlisted) and a [`HandshakeAuthorizer`]. There is no implicit
//!   "allow everyone": the builder requires either
//!   [`WebSocketServerBuilder::authorizer`] or the explicit
//!   [`WebSocketServerBuilder::allow_anonymous`].
//! - The handshake must complete within `handshake_timeout`, the number of
//!   concurrent connections is capped, frames/messages/write buffers are
//!   bounded, and each connection's outbound queue is bounded — a peer that
//!   stops reading is evicted rather than buffered without limit.

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

mod auth;
mod client;
mod connection;
mod error;
mod handler;
mod message;
mod room;
mod server;

pub use auth::{
    AllowAnonymous, HandshakeAuthorizer, HandshakeRejection, HandshakeRequest, OriginPolicy,
    Principal,
};
pub use client::{WebSocketClient, WebSocketClientBuilder};
pub use connection::{Connection, ConnectionId, ConnectionState};
pub use error::{WebSocketError, WebSocketResult};
pub use handler::{LoggingHandler, WebSocketHandler};
pub use message::{InvalidTextPayload, Message, MessageType};
pub use room::{Room, RoomId, RoomManager};
pub use server::{WebSocketServer, WebSocketServerBuilder, WebSocketServerConfig};

// Re-export commonly used types from tungstenite
pub use tungstenite::Message as RawMessage;
pub use tungstenite::protocol::CloseFrame;
