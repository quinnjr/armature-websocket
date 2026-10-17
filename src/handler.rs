//! WebSocket handler trait for implementing custom message handling.

use crate::auth::Principal;
use crate::message::Message;
use async_trait::async_trait;

/// Trait for handling WebSocket events.
///
/// Implement this trait to define custom behavior for WebSocket connections.
///
/// `on_connect`, `on_message` and `on_disconnect` receive the [`Principal`]
/// the server's [`HandshakeAuthorizer`](crate::HandshakeAuthorizer)
/// established for the connection during the upgrade.
#[async_trait]
pub trait WebSocketHandler: Send + Sync + 'static {
    /// Called when a new client connects.
    ///
    /// # Arguments
    /// * `connection_id` - The unique identifier for the connection
    /// * `principal` - The identity established during the upgrade
    async fn on_connect(&self, connection_id: &str, principal: &Principal) {
        let _ = (connection_id, principal);
    }

    /// Called when a message is received from a client.
    ///
    /// # Arguments
    /// * `connection_id` - The unique identifier for the connection
    /// * `principal` - The identity established during the upgrade
    /// * `message` - The received message
    async fn on_message(&self, connection_id: &str, principal: &Principal, message: Message);

    /// Called when a client disconnects.
    ///
    /// # Arguments
    /// * `connection_id` - The unique identifier for the connection
    /// * `principal` - The identity established during the upgrade
    async fn on_disconnect(&self, connection_id: &str, principal: &Principal) {
        let _ = (connection_id, principal);
    }

    /// Called when an error occurs on a connection.
    ///
    /// # Arguments
    /// * `connection_id` - The unique identifier for the connection
    /// * `error` - The error that occurred
    async fn on_error(&self, connection_id: &str, error: &crate::error::WebSocketError) {
        tracing::error!(connection_id = %connection_id, error = %error, "WebSocket error");
    }

    /// Called when a ping is received. Return the pong payload.
    ///
    /// # Arguments
    /// * `connection_id` - The unique identifier for the connection
    /// * `payload` - The ping payload
    ///
    /// # Returns
    /// The payload to send in the pong response
    async fn on_ping(&self, connection_id: &str, payload: &[u8]) -> Vec<u8> {
        let _ = connection_id;
        payload.to_vec()
    }

    /// Called when a pong is received.
    ///
    /// # Arguments
    /// * `connection_id` - The unique identifier for the connection
    /// * `payload` - The pong payload
    async fn on_pong(&self, connection_id: &str, payload: &[u8]) {
        let _ = (connection_id, payload);
    }
}

/// A no-op handler that logs messages.
#[derive(Debug, Default, Clone)]
pub struct LoggingHandler;

#[async_trait]
impl WebSocketHandler for LoggingHandler {
    async fn on_connect(&self, connection_id: &str, principal: &Principal) {
        tracing::info!(
            connection_id = %connection_id,
            subject = principal.subject().unwrap_or("<anonymous>"),
            "Client connected"
        );
    }

    async fn on_message(&self, connection_id: &str, _principal: &Principal, message: Message) {
        tracing::debug!(
            connection_id = %connection_id,
            message_type = ?message.message_type,
            payload_len = message.payload.len(),
            "Received message"
        );
    }

    async fn on_disconnect(&self, connection_id: &str, _principal: &Principal) {
        tracing::info!(connection_id = %connection_id, "Client disconnected");
    }
}
