//! Upgrade-time authorization: Origin allowlisting and the handshake
//! authorizer hook.
//!
//! A WebSocket upgrade is an ordinary HTTP `GET` that browsers will happily
//! send cross-site with the user's cookies attached. Without an `Origin`
//! check and an authentication step at upgrade time any web page the user
//! visits can open a socket to the server as that user (Cross-Site WebSocket
//! Hijacking). The server therefore runs every upgrade request through an
//! [`OriginPolicy`] and then a [`HandshakeAuthorizer`] before completing the
//! handshake; the resulting [`Principal`] is handed to the
//! [`WebSocketHandler`](crate::WebSocketHandler) callbacks for that
//! connection.

use std::collections::BTreeMap;
use std::fmt;

/// The HTTP upgrade request seen by the authorizer (headers, URI, method).
pub type HandshakeRequest = tungstenite::handshake::server::Request;

/// The authenticated identity of a WebSocket connection.
///
/// Produced by a [`HandshakeAuthorizer`] during the upgrade and passed to the
/// handler callbacks. Attribute values are redacted from `Debug` output
/// because authorizers commonly stash tokens or claims in them.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Principal {
    subject: Option<String>,
    attributes: BTreeMap<String, String>,
}

impl Principal {
    /// A principal for an authenticated subject (user id, client id, ...).
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: Some(subject.into()),
            attributes: BTreeMap::new(),
        }
    }

    /// The unauthenticated principal produced by [`AllowAnonymous`].
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// Attach an attribute (role, tenant, claim, ...).
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// The authenticated subject, or `None` for an anonymous principal.
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// Whether this principal is anonymous.
    pub fn is_anonymous(&self) -> bool {
        self.subject.is_none()
    }

    /// Look up an attribute.
    pub fn attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(String::as_str)
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Principal")
            .field("subject", &self.subject)
            .field(
                "attributes",
                &self
                    .attributes
                    .keys()
                    .map(|k| (k.as_str(), "[REDACTED]"))
                    .collect::<BTreeMap<_, _>>(),
            )
            .finish()
    }
}

/// Why an upgrade request was refused. Sent to the client as a plain HTTP
/// error response instead of `101 Switching Protocols`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRejection {
    status: http::StatusCode,
    reason: String,
}

impl HandshakeRejection {
    /// Reject with an explicit status and a client-visible reason.
    pub fn new(status: http::StatusCode, reason: impl Into<String>) -> Self {
        Self {
            status,
            reason: reason.into(),
        }
    }

    /// `401 Unauthorized`: credentials missing or invalid.
    pub fn unauthorized() -> Self {
        Self::new(http::StatusCode::UNAUTHORIZED, "Unauthorized")
    }

    /// `403 Forbidden`: authenticated but not allowed.
    pub fn forbidden() -> Self {
        Self::new(http::StatusCode::FORBIDDEN, "Forbidden")
    }

    /// The HTTP status sent to the client.
    pub fn status(&self) -> http::StatusCode {
        self.status
    }

    /// The client-visible reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Decides whether an upgrade request may become a WebSocket connection.
///
/// Runs synchronously inside the handshake, after the [`OriginPolicy`] check.
/// Verify a bearer token, session cookie or signed query parameter here and
/// return the resulting [`Principal`]; any `Err` refuses the upgrade.
///
/// Any `Fn(&HandshakeRequest) -> Result<Principal, HandshakeRejection>`
/// closure implements this trait.
///
/// ```
/// use armature_websocket::{HandshakeRejection, HandshakeRequest, Principal};
///
/// let authorizer = |req: &HandshakeRequest| {
///     match req.headers().get("authorization").and_then(|v| v.to_str().ok()) {
///         Some("Bearer s3cret") => Ok(Principal::new("alice")),
///         _ => Err(HandshakeRejection::unauthorized()),
///     }
/// };
/// # let _ = armature_websocket::WebSocketServerBuilder::new().authorizer(authorizer);
/// ```
pub trait HandshakeAuthorizer: Send + Sync + 'static {
    /// Authorize the upgrade request.
    fn authorize(&self, request: &HandshakeRequest) -> Result<Principal, HandshakeRejection>;
}

impl<F> HandshakeAuthorizer for F
where
    F: Fn(&HandshakeRequest) -> Result<Principal, HandshakeRejection> + Send + Sync + 'static,
{
    fn authorize(&self, request: &HandshakeRequest) -> Result<Principal, HandshakeRejection> {
        self(request)
    }
}

/// Explicit opt-out of upgrade authentication: every request that passes the
/// [`OriginPolicy`] becomes a connection with [`Principal::anonymous`].
///
/// Selected via
/// [`WebSocketServerBuilder::allow_anonymous`](crate::WebSocketServerBuilder::allow_anonymous);
/// the server logs a warning when it starts with it.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAnonymous;

impl HandshakeAuthorizer for AllowAnonymous {
    fn authorize(&self, _request: &HandshakeRequest) -> Result<Principal, HandshakeRejection> {
        Ok(Principal::anonymous())
    }
}

/// Which browser origins may open a connection.
///
/// Browsers always send an `Origin` header on a WebSocket upgrade, so it is
/// the CSWSH defence. A request **without** an `Origin` header comes from a
/// non-browser client (a CLI, a backend service) that a hostile web page
/// cannot drive, so the origin check admits it and leaves it to the
/// [`HandshakeAuthorizer`]. A request carrying an `Origin` (including the
/// opaque `null` origin) is admitted only if that origin is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OriginPolicy {
    /// Only these exact origins (`scheme://host[:port]`, compared
    /// case-insensitively, trailing `/` ignored). An empty list — the
    /// default — rejects every browser origin.
    AllowList(Vec<String>),
    /// Any origin. Disables the CSWSH defence; only for development or when
    /// the authorizer does not rely on ambient (cookie) credentials.
    Any,
}

impl Default for OriginPolicy {
    fn default() -> Self {
        OriginPolicy::AllowList(Vec::new())
    }
}

fn normalize_origin(origin: &str) -> String {
    origin.trim().trim_end_matches('/').to_ascii_lowercase()
}

impl OriginPolicy {
    /// Apply the policy to an upgrade request.
    pub fn check(&self, request: &HandshakeRequest) -> Result<(), HandshakeRejection> {
        let mut origins = request.headers().get_all(http::header::ORIGIN).iter();
        let Some(origin) = origins.next() else {
            return Ok(());
        };
        if origins.next().is_some() {
            return Err(HandshakeRejection::new(
                http::StatusCode::FORBIDDEN,
                "Multiple Origin headers",
            ));
        }
        let rejected =
            || HandshakeRejection::new(http::StatusCode::FORBIDDEN, "Origin not allowed");
        match self {
            OriginPolicy::Any => Ok(()),
            OriginPolicy::AllowList(allowed) => {
                let origin = normalize_origin(origin.to_str().map_err(|_| rejected())?);
                if allowed.iter().any(|a| normalize_origin(a) == origin) {
                    Ok(())
                } else {
                    Err(rejected())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(origins: &[&str]) -> HandshakeRequest {
        let mut builder = http::Request::builder().uri("/ws");
        for o in origins {
            builder = builder.header(http::header::ORIGIN, *o);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn default_policy_rejects_every_browser_origin() {
        let policy = OriginPolicy::default();
        assert!(policy.check(&request(&["https://evil.example"])).is_err());
        assert!(policy.check(&request(&["null"])).is_err());
    }

    #[test]
    fn missing_origin_is_admitted_for_non_browser_clients() {
        assert!(OriginPolicy::default().check(&request(&[])).is_ok());
    }

    #[test]
    fn allowlist_matches_case_insensitively_and_rejects_others() {
        let policy = OriginPolicy::AllowList(vec!["https://App.example.com/".into()]);
        assert!(policy.check(&request(&["https://app.example.com"])).is_ok());
        assert!(
            policy
                .check(&request(&["https://app.example.com.evil.net"]))
                .is_err()
        );
        assert!(policy.check(&request(&["http://app.example.com"])).is_err());
    }

    #[test]
    fn duplicate_origin_headers_are_rejected() {
        let policy = OriginPolicy::Any;
        assert!(
            policy
                .check(&request(&["https://a.example", "https://b.example"]))
                .is_err()
        );
    }

    #[test]
    fn principal_debug_redacts_attribute_values() {
        let p = Principal::new("alice").with_attribute("token", "sk_live_secret");
        let dbg = format!("{p:?}");
        assert!(dbg.contains("alice"));
        assert!(dbg.contains("token"));
        assert!(!dbg.contains("sk_live_secret"));
    }
}
