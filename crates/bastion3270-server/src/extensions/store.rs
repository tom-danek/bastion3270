//! Extension point **D — [`SessionStore`]**: where live gateway sessions are registered.
//!
//! Default implementation: [`InMemorySessionStore`] — one pod; a pod restart drops its sessions.
//!
//! A TN3270 session is a live TCP/TLS connection owned by exactly one pod, so a store never
//! moves sockets between pods; it only registers which sessions exist.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use crate::gateway::{GatewaySession, SessionId};

/// Extension trait for registering gateway sessions.
#[async_trait]
pub trait SessionStore: Send + Sync + core::fmt::Debug + 'static {
    /// Registers a newly opened session.
    ///
    /// # Errors
    /// Returns a human-readable reason if the registry rejects the session.
    async fn insert(&self, session: Arc<GatewaySession>) -> Result<(), String>;

    /// Looks up a session by id.
    async fn get(&self, id: &SessionId) -> Option<Arc<GatewaySession>>;

    /// Removes a session; returns it if it was present.
    async fn remove(&self, id: &SessionId) -> Option<Arc<GatewaySession>>;

    /// Snapshot of all sessions known to this pod (limits, reaper, admin views).
    async fn sessions(&self) -> Vec<Arc<GatewaySession>>;
}

/// Default store: a `HashMap` behind a `std::sync::RwLock`.
///
/// A *synchronous* lock is correct here because it is never held across an `.await`:
/// every method takes the lock, touches the map and releases it immediately.
#[derive(Debug, Default)]
pub struct InMemorySessionStore {
    map: RwLock<HashMap<SessionId, Arc<GatewaySession>>>,
}

impl InMemorySessionStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn insert(&self, session: Arc<GatewaySession>) -> Result<(), String> {
        let mut map = self
            .map
            .write()
            .map_err(|_| "session map lock poisoned".to_owned())?;
        map.insert(session.id(), session);
        Ok(())
    }

    async fn get(&self, id: &SessionId) -> Option<Arc<GatewaySession>> {
        self.map.read().ok()?.get(id).cloned()
    }

    async fn remove(&self, id: &SessionId) -> Option<Arc<GatewaySession>> {
        self.map.write().ok()?.remove(id)
    }

    async fn sessions(&self) -> Vec<Arc<GatewaySession>> {
        self.map
            .read()
            .map_or_default(|m| m.values().cloned().collect())
    }
}
