//! # VCL Connection Pool
//!
//! [`VCLPool`] manages multiple [`VCLConnection`]s under a single manager.
//!
//! Useful when you need to handle many peers simultaneously —
//! for example a server accepting connections from multiple clients,
//! or a client maintaining connections to multiple servers.
//!
//! ## Example
//!
//! ```no_run
//! use vcl_protocol::pool::VCLPool;
//!
//! #[tokio::main]
//! async fn main() {
//!     let mut pool = VCLPool::new(10);
//!
//!     let id = pool.bind("127.0.0.1:0").await.unwrap();
//!     pool.connect(id, "127.0.0.1:8080").await.unwrap();
//!     pool.send(id, b"Hello from pool!").await.unwrap();
//!
//!     let packet = pool.recv(id).await.unwrap();
//!     println!("{}", String::from_utf8_lossy(&packet.payload));
//!
//!     pool.close(id).unwrap();
//! }
//! ```

use crate::connection::VCLConnection;
use crate::error::VCLError;
use crate::packet::VCLPacket;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// A unique identifier for a connection inside a [`VCLPool`].
pub type ConnectionId = u64;

/// Manages multiple [`VCLConnection`]s under a single pool.
///
/// Each connection gets a unique [`ConnectionId`] assigned at `bind()`.
/// The pool enforces a maximum connection limit set at construction.
pub struct VCLPool {
    connections: HashMap<ConnectionId, VCLConnection>,
    next_id: ConnectionId,
    max_connections: usize,
}

impl VCLPool {
    /// Create a new pool with a maximum number of concurrent connections.
    ///
    /// # Example
    /// ```
    /// use vcl_protocol::pool::VCLPool;
    /// let pool = VCLPool::new(10);
    /// ```
    pub fn new(max_connections: usize) -> Self {
        info!(max_connections, "VCLPool created");
        VCLPool {
            connections: HashMap::new(),
            next_id: 0,
            max_connections,
        }
    }

    /// Bind a new connection to a local UDP address and add it to the pool.
    ///
    /// Returns the [`ConnectionId`] assigned to this connection.
    ///
    /// # Errors
    /// - [`VCLError::InvalidPacket`] — pool is at maximum capacity
    /// - [`VCLError::IoError`] — socket bind failed
    pub async fn bind(&mut self, addr: &str) -> Result<ConnectionId, VCLError> {
        if self.connections.len() >= self.max_connections {
            warn!(
                current = self.connections.len(),
                max = self.max_connections,
                "Pool is at maximum capacity"
            );
            return Err(VCLError::InvalidPacket(format!(
                "Pool is full: max {} connections",
                self.max_connections
            )));
        }

        let conn = VCLConnection::bind(addr).await?;
        let id = self.next_id;
        self.next_id += 1;
        self.connections.insert(id, conn);
        info!(id, addr, "Connection added to pool");
        Ok(id)
    }

    /// Connect a pooled connection to a remote peer (client side handshake).
    ///
    /// # Errors
    /// - [`VCLError::InvalidPacket`] — connection ID not found
    /// - [`VCLError::HandshakeFailed`] — handshake failed
    pub async fn connect(&mut self, id: ConnectionId, addr: &str) -> Result<(), VCLError> {
        let conn = self.get_mut(id)?;
        debug!(id, peer = %addr, "Pool: connecting");
        conn.connect(addr).await
    }

    /// Accept an incoming handshake on a pooled connection (server side).
    ///
    /// # Errors
    /// - [`VCLError::InvalidPacket`] — connection ID not found
    /// - [`VCLError::HandshakeFailed`] — handshake failed
    pub async fn accept_handshake(&mut self, id: ConnectionId) -> Result<(), VCLError> {
        let conn = self.get_mut(id)?;
        debug!(id, "Pool: accepting handshake");
        conn.accept_handshake().await
    }

    /// Send data on a pooled connection.
    ///
    /// # Errors
    /// - [`VCLError::InvalidPacket`] — connection ID not found
    /// - Any error from [`VCLConnection::send`]
    pub async fn send(&mut self, id: ConnectionId, data: &[u8]) -> Result<(), VCLError> {
        let conn = self.get_mut(id)?;
        debug!(id, size = data.len(), "Pool: sending");
        conn.send(data).await
    }

    /// Receive the next data packet on a pooled connection.
    ///
    /// # Errors
    /// - [`VCLError::InvalidPacket`] — connection ID not found
    /// - Any error from [`VCLConnection::recv`]
    pub async fn recv(&mut self, id: ConnectionId) -> Result<VCLPacket, VCLError> {
        let conn = self.get_mut(id)?;
        debug!(id, "Pool: waiting for packet");
        conn.recv().await
    }

    /// Send a ping on a pooled connection.
    ///
    /// # Errors
    /// - [`VCLError::InvalidPacket`] — connection ID not found
    /// - Any error from [`VCLConnection::ping`]
    pub async fn ping(&mut self, id: ConnectionId) -> Result<(), VCLError> {
        let conn = self.get_mut(id)?;
        debug!(id, "Pool: sending ping");
        conn.ping().await
    }

    /// Rotate keys on a pooled connection.
    ///
    /// # Errors
    /// - [`VCLError::InvalidPacket`] — connection ID not found
    /// - Any error from [`VCLConnection::rotate_keys`]
    pub async fn rotate_keys(&mut self, id: ConnectionId) -> Result<(), VCLError> {
        let conn = self.get_mut(id)?;
        debug!(id, "Pool: rotating keys");
        conn.rotate_keys().await
    }

    /// Close a specific connection and remove it from the pool.
    ///
    /// # Errors
    /// - [`VCLError::InvalidPacket`] — connection ID not found
    /// - [`VCLError::ConnectionClosed`] — already closed
    pub fn close(&mut self, id: ConnectionId) -> Result<(), VCLError> {
        match self.connections.get_mut(&id) {
            Some(conn) => {
                conn.close()?;
                self.connections.remove(&id);
                info!(id, "Connection removed from pool");
                Ok(())
            }
            None => {
                warn!(id, "close() called with unknown connection ID");
                Err(VCLError::InvalidPacket(format!(
                    "Connection ID {} not found in pool",
                    id
                )))
            }
        }
    }

    /// Close all connections and clear the pool.
    pub fn close_all(&mut self) {
        info!(count = self.connections.len(), "Closing all pool connections");
        for (id, conn) in self.connections.iter_mut() {
            if let Err(e) = conn.close() {
                warn!(id, error = %e, "Error closing connection during close_all");
            }
        }
        self.connections.clear();
    }

    /// Returns the number of active connections in the pool.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Returns `true` if the pool has no active connections.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Returns `true` if the pool has reached its maximum capacity.
    pub fn is_full(&self) -> bool {
        self.connections.len() >= self.max_connections
    }

    /// Returns a list of all active [`ConnectionId`]s in the pool.
    pub fn connection_ids(&self) -> Vec<ConnectionId> {
        self.connections.keys().copied().collect()
    }

    /// Returns `true` if a connection with the given ID exists in the pool.
    pub fn contains(&self, id: ConnectionId) -> bool {
        self.connections.contains_key(&id)
    }

    /// Get a reference to a connection by ID.
    ///
    /// # Errors
    /// Returns [`VCLError::InvalidPacket`] if the ID is not found.
    pub fn get(&self, id: ConnectionId) -> Result<&VCLConnection, VCLError> {
        self.connections.get(&id).ok_or_else(|| {
            VCLError::InvalidPacket(format!("Connection ID {} not found in pool", id))
        })
    }

    fn get_mut(&mut self, id: ConnectionId) -> Result<&mut VCLConnection, VCLError> {
        self.connections.get_mut(&id).ok_or_else(|| {
            VCLError::InvalidPacket(format!("Connection ID {} not found in pool", id))
        })
    }
}

impl Drop for VCLPool {
    fn drop(&mut self) {
        if !self.connections.is_empty() {
            self.close_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_new() {
        let pool = VCLPool::new(5);
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
        assert!(!pool.is_full());
    }

    #[tokio::test]
    async fn test_pool_bind() {
        let mut pool = VCLPool::new(5);
        let id = pool.bind("127.0.0.1:0").await.unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(id));
        assert!(!pool.is_empty());
    }

    #[tokio::test]
    async fn test_pool_max_capacity() {
        let mut pool = VCLPool::new(2);
        pool.bind("127.0.0.1:0").await.unwrap();
        pool.bind("127.0.0.1:0").await.unwrap();
        assert!(pool.is_full());
        let result = pool.bind("127.0.0.1:0").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pool_close() {
        let mut pool = VCLPool::new(5);
        let id = pool.bind("127.0.0.1:0").await.unwrap();
        assert_eq!(pool.len(), 1);
        pool.close(id).unwrap();
        assert_eq!(pool.len(), 0);
        assert!(!pool.contains(id));
    }

    #[tokio::test]
    async fn test_pool_close_all() {
        let mut pool = VCLPool::new(5);
        pool.bind("127.0.0.1:0").await.unwrap();
        pool.bind("127.0.0.1:0").await.unwrap();
        pool.bind("127.0.0.1:0").await.unwrap();
        assert_eq!(pool.len(), 3);
        pool.close_all();
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn test_pool_unknown_id() {
        let mut pool = VCLPool::new(5);
        let result = pool.close(999);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pool_connection_ids() {
        let mut pool = VCLPool::new(5);
        let id1 = pool.bind("127.0.0.1:0").await.unwrap();
        let id2 = pool.bind("127.0.0.1:0").await.unwrap();
        let mut ids = pool.connection_ids();
        ids.sort();
        assert_eq!(ids, vec![id1, id2]);
    }
}
