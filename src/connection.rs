//! WebSocket connection management.

use crate::auth::Principal;
use crate::error::{WebSocketError, WebSocketResult};
use crate::message::Message;
use futures_util::SinkExt;
use futures_util::stream::SplitSink;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::WebSocketStream;

/// Unique identifier for a connection.
pub type ConnectionId = String;

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionState {
    /// Connection is being established
    Connecting,
    /// Connection is open and ready
    Open,
    /// Connection is closing
    Closing,
    /// Connection is closed
    Closed,
}

/// A WebSocket connection.
pub struct Connection {
    /// Unique connection identifier
    pub id: ConnectionId,
    /// Remote address
    pub remote_addr: Option<SocketAddr>,
    /// Connection state
    state: Arc<RwLock<ConnectionState>>,
    /// Authenticated identity established at upgrade time
    principal: Arc<Principal>,
    /// Sender for outgoing messages (bounded: see [`Connection::send`])
    tx: mpsc::Sender<Message>,
    /// Wakes the server's read loop when the connection must be torn down
    /// without the peer's cooperation (slow consumer eviction).
    evict: Arc<Notify>,
}

impl Connection {
    /// Create a new connection.
    pub(crate) fn new(
        id: ConnectionId,
        remote_addr: Option<SocketAddr>,
        principal: Arc<Principal>,
        tx: mpsc::Sender<Message>,
    ) -> Self {
        Self {
            id,
            remote_addr,
            state: Arc::new(RwLock::new(ConnectionState::Open)),
            principal,
            tx,
            evict: Arc::new(Notify::new()),
        }
    }

    /// The identity the [`HandshakeAuthorizer`](crate::HandshakeAuthorizer)
    /// established for this connection.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Get the connection state.
    pub fn state(&self) -> ConnectionState {
        *self.state.read()
    }

    /// Check if the connection is open.
    pub fn is_open(&self) -> bool {
        self.state() == ConnectionState::Open
    }

    /// Queue a message for this connection.
    ///
    /// Never blocks. The per-connection outbound queue is bounded
    /// ([`WebSocketServerConfig::outbound_queue_capacity`](crate::WebSocketServerConfig));
    /// if it is full the peer is not reading fast enough, so instead of
    /// buffering without limit (or stalling a room broadcast on one slow
    /// member) the connection is evicted: it moves to
    /// [`ConnectionState::Closing`], the server tears it down, and this call
    /// returns [`WebSocketError::SlowConsumer`].
    pub fn send(&self, message: Message) -> WebSocketResult<()> {
        if !self.is_open() {
            return Err(WebSocketError::ConnectionClosed);
        }
        match self.tx.try_send(message) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(connection_id = %self.id, "Outbound queue full; evicting slow consumer");
                self.evict();
                Err(WebSocketError::SlowConsumer)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(WebSocketError::ConnectionClosed),
        }
    }

    /// Send a text message.
    pub fn send_text<S: Into<String>>(&self, text: S) -> WebSocketResult<()> {
        self.send(Message::text(text))
    }

    /// Send a binary message.
    pub fn send_binary<B: Into<bytes::Bytes>>(&self, data: B) -> WebSocketResult<()> {
        self.send(Message::binary(data))
    }

    /// Send a JSON message.
    pub fn send_json<T: serde::Serialize>(&self, value: &T) -> WebSocketResult<()> {
        let message = Message::json(value)?;
        self.send(message)
    }

    /// Close the connection.
    ///
    /// Queues a Close frame; if the queue is full the connection is evicted
    /// instead, so a close request is never silently lost.
    pub fn close(&self) {
        *self.state.write() = ConnectionState::Closing;
        if self.tx.try_send(Message::close()).is_err() {
            self.evict.notify_one();
        }
    }

    /// Mark the connection closing and wake the server's read loop so it
    /// tears the connection down.
    fn evict(&self) {
        *self.state.write() = ConnectionState::Closing;
        self.evict.notify_one();
    }

    /// Resolves once the connection has been evicted (see [`Self::send`]).
    pub(crate) async fn evicted(&self) {
        self.evict.notified().await;
    }

    /// Set the connection state (internal use).
    ///
    /// `close()` moves the state to `Closing`; the server's connection loop
    /// calls this with `ConnectionState::Closed` once the read/write tasks
    /// have terminated and teardown is complete, so the state machine actually
    /// reaches `Closed`.
    pub(crate) fn set_state(&self, state: ConnectionState) {
        *self.state.write() = state;
    }
}

impl Clone for Connection {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            remote_addr: self.remote_addr,
            state: Arc::clone(&self.state),
            principal: Arc::clone(&self.principal),
            tx: self.tx.clone(),
            evict: Arc::clone(&self.evict),
        }
    }
}

/// Manages the write side of a WebSocket connection.
pub(crate) struct ConnectionWriter {
    sink: SplitSink<WebSocketStream<TcpStream>, tungstenite::Message>,
    rx: mpsc::Receiver<Message>,
}

impl ConnectionWriter {
    /// Create a new connection writer.
    pub fn new(
        sink: SplitSink<WebSocketStream<TcpStream>, tungstenite::Message>,
        rx: mpsc::Receiver<Message>,
    ) -> Self {
        Self { sink, rx }
    }

    /// Run the writer loop, sending messages from the channel to the WebSocket.
    pub async fn run(mut self) -> WebSocketResult<()> {
        while let Some(message) = self.rx.recv().await {
            let is_close = message.is_close();
            // A text message with a non-UTF-8 payload cannot go on the wire
            // (RFC 6455 §5.6). Drop that one message and keep the connection
            // running rather than lossily corrupting it into U+FFFD runs.
            let raw_message: tungstenite::Message = match message.try_into() {
                Ok(raw) => raw,
                Err(e) => {
                    tracing::error!(error = %e, "Dropping unsendable WebSocket message");
                    continue;
                }
            };

            if let Err(e) = self.sink.send(raw_message).await {
                tracing::error!(error = %e, "Failed to send WebSocket message");
                return Err(WebSocketError::Protocol(e));
            }

            if is_close {
                break;
            }
        }

        // Gracefully close the sink
        let _ = self.sink.close().await;
        Ok(())
    }
}
