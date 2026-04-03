//! # VCL Packet Fragmentation
//!
//! Splits large payloads into fragments and reassembles them on the receiver side.
//!
//! Each fragment carries:
//! - `fragment_id` — unique ID for this fragmented message
//! - `fragment_index` — position of this fragment (0-based)
//! - `total_fragments` — total number of fragments in this message
//! - `data` — the fragment payload
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::fragment::{Fragmenter, Reassembler};
//!
//! let data = vec![0u8; 5000];
//! let fragments = Fragmenter::split(&data, 1200, 1);
//! assert!(fragments.len() > 1);
//!
//! let mut reassembler = Reassembler::new();
//! for f in fragments {
//!     if let Some(result) = reassembler.add(f) {
//!         assert_eq!(result, vec![0u8; 5000]);
//!     }
//! }
//! ```

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tracing::{debug, warn};

/// A single fragment of a larger payload.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Fragment {
    /// Unique ID for the fragmented message this fragment belongs to.
    pub fragment_id: u64,
    /// Zero-based index of this fragment within the message.
    pub fragment_index: u16,
    /// Total number of fragments in this message.
    pub total_fragments: u16,
    /// The fragment payload bytes.
    pub data: Vec<u8>,
}

impl Fragment {
    /// Returns `true` if this is the last fragment in the message.
    pub fn is_last(&self) -> bool {
        self.fragment_index == self.total_fragments - 1
    }

    /// Returns `true` if this message was not fragmented (single fragment).
    pub fn is_single(&self) -> bool {
        self.total_fragments == 1
    }
}

/// Splits payloads into [`Fragment`]s.
pub struct Fragmenter;

impl Fragmenter {
    /// Split `data` into fragments of at most `fragment_size` bytes.
    ///
    /// If `data` fits within `fragment_size`, returns a single fragment.
    ///
    /// # Arguments
    /// - `data` — the payload to fragment
    /// - `fragment_size` — maximum bytes per fragment
    /// - `fragment_id` — unique ID for this message (use a counter or random u64)
    ///
    /// # Panics
    /// Panics if `fragment_size` is 0.
    pub fn split(data: &[u8], fragment_size: usize, fragment_id: u64) -> Vec<Fragment> {
        assert!(fragment_size > 0, "fragment_size must be > 0");

        let chunks: Vec<&[u8]> = data.chunks(fragment_size).collect();
        let total = chunks.len() as u16;

        debug!(
            fragment_id,
            total_size = data.len(),
            fragment_size,
            total_fragments = total,
            "Splitting payload into fragments"
        );

        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| Fragment {
                fragment_id,
                fragment_index: i as u16,
                total_fragments: total,
                data: chunk.to_vec(),
            })
            .collect()
    }

    /// Returns `true` if `data` needs fragmentation given `fragment_size`.
    pub fn needs_split(data: &[u8], fragment_size: usize) -> bool {
        data.len() > fragment_size
    }
}

/// Tracks incoming fragments and reassembles complete messages.
///
/// Each `fragment_id` is tracked independently.
/// Once all fragments for a message arrive, [`Reassembler::add`] returns `Some(data)`.
///
/// Old incomplete messages are evicted when [`Reassembler::cleanup`] is called.
pub struct Reassembler {
    /// Map from fragment_id to (received fragments, total expected)
    pending: HashMap<u64, ReassemblyBuffer>,
    /// Maximum number of incomplete messages tracked simultaneously.
    max_pending: usize,
}

struct ReassemblyBuffer {
    fragments: HashMap<u16, Vec<u8>>,
    total: u16,
}

impl Reassembler {
    /// Create a new reassembler with a default max of 256 pending messages.
    pub fn new() -> Self {
        Reassembler {
            pending: HashMap::new(),
            max_pending: 256,
        }
    }

    /// Create a new reassembler with a custom max pending messages limit.
    pub fn with_max_pending(max_pending: usize) -> Self {
        Reassembler {
            pending: HashMap::new(),
            max_pending,
        }
    }

    /// Add a fragment. Returns `Some(data)` when all fragments are received.
    ///
    /// Returns `None` if more fragments are still expected.
    /// Silently drops duplicate fragments.
    pub fn add(&mut self, fragment: Fragment) -> Option<Vec<u8>> {
        // Drop if too many pending messages
        if !self.pending.contains_key(&fragment.fragment_id)
            && self.pending.len() >= self.max_pending
        {
            warn!(
                fragment_id = fragment.fragment_id,
                max_pending = self.max_pending,
                "Reassembler at capacity, dropping fragment"
            );
            return None;
        }

        let id = fragment.fragment_id;
        let total = fragment.total_fragments;
        let index = fragment.fragment_index;

        // Single fragment shortcut
        if fragment.is_single() {
            debug!(fragment_id = id, "Single fragment, no reassembly needed");
            return Some(fragment.data);
        }

        let buffer = self.pending.entry(id).or_insert_with(|| {
            debug!(fragment_id = id, total_fragments = total, "New reassembly buffer");
            ReassemblyBuffer {
                fragments: HashMap::new(),
                total,
            }
        });

        // Ignore duplicate
        if buffer.fragments.contains_key(&index) {
            warn!(fragment_id = id, index, "Duplicate fragment ignored");
            return None;
        }

        buffer.fragments.insert(index, fragment.data);
        debug!(
            fragment_id = id,
            received = buffer.fragments.len(),
            total = buffer.total,
            "Fragment received"
        );

        // Check if complete
        if buffer.fragments.len() == buffer.total as usize {
            let buf = self.pending.remove(&id).unwrap();
            debug!(fragment_id = id, "Reassembly complete");
            return Some(Self::assemble(buf));
        }

        None
    }

    /// Returns the number of incomplete messages currently being tracked.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Remove all pending incomplete messages.
    pub fn cleanup(&mut self) {
        let count = self.pending.len();
        self.pending.clear();
        if count > 0 {
            warn!(dropped = count, "Reassembler cleanup: dropped incomplete messages");
        }
    }

    fn assemble(buf: ReassemblyBuffer) -> Vec<u8> {
        let mut indices: Vec<u16> = buf.fragments.keys().copied().collect();
        indices.sort_unstable();
        indices
            .into_iter()
            .flat_map(|i| buf.fragments[&i].clone())
            .collect()
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_fragmentation_needed() {
        let data = vec![1u8; 100];
        assert!(!Fragmenter::needs_split(&data, 1200));
    }

    #[test]
    fn test_fragmentation_needed() {
        let data = vec![1u8; 5000];
        assert!(Fragmenter::needs_split(&data, 1200));
    }

    #[test]
    fn test_single_fragment() {
        let data = vec![42u8; 500];
        let frags = Fragmenter::split(&data, 1200, 1);
        assert_eq!(frags.len(), 1);
        assert!(frags[0].is_single());
        assert_eq!(frags[0].data, data);
    }

    #[test]
    fn test_split_exact() {
        let data = vec![0u8; 2400];
        let frags = Fragmenter::split(&data, 1200, 2);
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].fragment_index, 0);
        assert_eq!(frags[1].fragment_index, 1);
        assert!(frags[1].is_last());
    }

    #[test]
    fn test_split_remainder() {
        let data = vec![0u8; 2500];
        let frags = Fragmenter::split(&data, 1200, 3);
        assert_eq!(frags.len(), 3);
        assert_eq!(frags[2].data.len(), 100);
    }

    #[test]
    fn test_reassemble_in_order() {
        let data: Vec<u8> = (0..255).collect();
        let frags = Fragmenter::split(&data, 50, 10);
        let mut r = Reassembler::new();
        let mut result = None;
        for f in frags {
            result = r.add(f);
        }
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_reassemble_out_of_order() {
        let data: Vec<u8> = (0..255).collect();
        let mut frags = Fragmenter::split(&data, 50, 11);
        frags.reverse(); // send last fragment first
        let mut r = Reassembler::new();
        let mut result = None;
        for f in frags {
            result = r.add(f);
        }
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_reassemble_single() {
        let data = vec![1u8; 100];
        let frags = Fragmenter::split(&data, 1200, 5);
        assert_eq!(frags.len(), 1);
        let mut r = Reassembler::new();
        let result = r.add(frags.into_iter().next().unwrap());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_duplicate_fragment_ignored() {
        let data: Vec<u8> = (0..200).collect();
        let frags = Fragmenter::split(&data, 50, 20);
        let mut r = Reassembler::new();
        let dup = frags[0].clone();
        r.add(frags[0].clone());
        r.add(dup); // duplicate — ignored
        assert_eq!(r.pending_count(), 1);
    }

    #[test]
    fn test_multiple_messages() {
        let data1: Vec<u8> = vec![1u8; 3000];
        let data2: Vec<u8> = vec![2u8; 2500];
        let frags1 = Fragmenter::split(&data1, 1200, 100);
        let frags2 = Fragmenter::split(&data2, 1200, 101);

        let mut r = Reassembler::new();
        let mut result1 = None;
        let mut result2 = None;

        // Interleave fragments from both messages
        let max = frags1.len().max(frags2.len());
        for i in 0..max {
            if i < frags1.len() {
                result1 = r.add(frags1[i].clone());
            }
            if i < frags2.len() {
                result2 = r.add(frags2[i].clone());
            }
        }

        assert_eq!(result1.unwrap(), data1);
        assert_eq!(result2.unwrap(), data2);
    }

    #[test]
    fn test_cleanup() {
        let data: Vec<u8> = vec![0u8; 3000];
        let frags = Fragmenter::split(&data, 1200, 99);
        let mut r = Reassembler::new();
        r.add(frags[0].clone()); // only first fragment, incomplete
        assert_eq!(r.pending_count(), 1);
        r.cleanup();
        assert_eq!(r.pending_count(), 0);
    }

    #[test]
    fn test_large_payload() {
        let data: Vec<u8> = (0..=255).cycle().take(65000).collect();
        let frags = Fragmenter::split(&data, 1200, 42);
        assert!(frags.len() > 1);
        let mut r = Reassembler::new();
        let mut result = None;
        for f in frags {
            result = r.add(f);
        }
        assert_eq!(result.unwrap(), data);
    }
}
