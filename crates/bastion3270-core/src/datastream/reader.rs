//! Zero-panic byte reader adhering strictly to `#![deny(clippy::indexing_slicing)]`.

use crate::datastream::DatastreamError;

/// Zero-panic, bounds-checked slice cursor for 3270 data stream parsing.
///
/// Under `#![deny(clippy::indexing_slicing)]`, direct slice indexing is forbidden.
/// [`ByteReader`] uses exclusively [`.get()`](slice::get) and safe iterator methods.
#[derive(Debug, Clone)]
pub struct ByteReader<'a> {
    slice: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    /// Creates a new [`ByteReader`] wrapping the provided byte slice.
    pub const fn new(slice: &'a [u8]) -> Self {
        Self { slice, offset: 0 }
    }

    /// Returns the current read offset within the slice.
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the number of unread bytes remaining in the stream.
    pub const fn remaining(&self) -> usize {
        self.slice.len().saturating_sub(self.offset)
    }

    /// Returns `true` if all bytes have been consumed.
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Returns `true` if at least `count` unread bytes are available.
    pub const fn has_remaining(&self, count: usize) -> bool {
        self.remaining() >= count
    }

    /// Peeks at the next byte without advancing the cursor.
    pub fn peek_byte(&self) -> Option<u8> {
        self.slice.get(self.offset).copied()
    }

    /// Peeks at the byte at `offset + delta` without advancing the cursor.
    pub fn peek_byte_at(&self, delta: usize) -> Option<u8> {
        self.offset
            .checked_add(delta)
            .and_then(|idx| self.slice.get(idx).copied())
    }

    /// Reads a single byte and advances the cursor by 1.
    ///
    /// # Errors
    ///
    /// Returns [`DatastreamError::UnexpectedEof`] if no bytes remain.
    pub fn read_byte(&mut self) -> Result<u8, DatastreamError> {
        match self.slice.get(self.offset) {
            Some(&byte) => {
                self.offset = self.offset.saturating_add(1);
                Ok(byte)
            }
            None => Err(DatastreamError::UnexpectedEof {
                expected: "byte",
                needed: 1,
                remaining: 0,
            }),
        }
    }

    /// Reads exactly `count` bytes and advances the cursor by `count`.
    ///
    /// # Errors
    ///
    /// Returns [`DatastreamError::UnexpectedEof`] if fewer than `count` bytes remain.
    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], DatastreamError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(DatastreamError::UnexpectedEof {
                expected: "bytes",
                needed: count,
                remaining: self.remaining(),
            })?;
        match self.slice.get(self.offset..end) {
            Some(subslice) => {
                self.offset = end;
                Ok(subslice)
            }
            None => Err(DatastreamError::UnexpectedEof {
                expected: "bytes",
                needed: count,
                remaining: self.remaining(),
            }),
        }
    }

    /// Reads two bytes as big-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`DatastreamError::UnexpectedEof`] if fewer than 2 bytes remain.
    pub fn read_u16_be(&mut self) -> Result<u16, DatastreamError> {
        let slice = self.read_bytes(2)?;
        match slice {
            &[b0, b1] => Ok(u16::from_be_bytes([b0, b1])),
            _ => Err(DatastreamError::UnexpectedEof {
                expected: "be_u16",
                needed: 2,
                remaining: slice.len(),
            }),
        }
    }

    /// Reads two bytes as a pair `(u8, u8)`.
    ///
    /// # Errors
    ///
    /// Returns [`DatastreamError::UnexpectedEof`] if fewer than 2 bytes remain.
    pub fn read_two_bytes(&mut self) -> Result<(u8, u8), DatastreamError> {
        let slice = self.read_bytes(2)?;
        match slice {
            &[b0, b1] => Ok((b0, b1)),
            _ => Err(DatastreamError::UnexpectedEof {
                expected: "two_bytes",
                needed: 2,
                remaining: slice.len(),
            }),
        }
    }

    /// Returns the entire remaining unread slice.
    pub fn remaining_slice(&self) -> &'a [u8] {
        self.slice.get(self.offset..).unwrap_or(&[])
    }

    /// Consumes and returns the entire remaining unread slice.
    pub fn read_remaining(&mut self) -> &'a [u8] {
        let rem = self.remaining_slice();
        self.offset = self.slice.len();
        rem
    }

    /// Advances the cursor forward by `count` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DatastreamError::UnexpectedEof`] if fewer than `count` bytes remain.
    pub fn advance(&mut self, count: usize) -> Result<(), DatastreamError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(DatastreamError::UnexpectedEof {
                expected: "advance",
                needed: count,
                remaining: self.remaining(),
            })?;
        if end > self.slice.len() {
            return Err(DatastreamError::UnexpectedEof {
                expected: "advance",
                needed: count,
                remaining: self.remaining(),
            });
        }
        self.offset = end;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_reader_basic() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut r = ByteReader::new(&data);
        assert_eq!(r.remaining(), 4);
        assert!(!r.is_empty());
        assert_eq!(r.peek_byte(), Some(0x01));
        assert_eq!(r.peek_byte_at(2), Some(0x03));
        assert_eq!(r.read_byte().unwrap(), 0x01);
        assert_eq!(r.offset(), 1);
        assert_eq!(r.read_bytes(2).unwrap(), &[0x02, 0x03]);
        assert_eq!(r.offset(), 3);
        assert_eq!(r.read_byte().unwrap(), 0x04);
        assert!(r.is_empty());
        assert!(r.read_byte().is_err());
    }

    #[test]
    fn test_byte_reader_u16_be_and_two_bytes() {
        let data = [0x12, 0x34, 0xAB, 0xCD];
        let mut r = ByteReader::new(&data);
        assert_eq!(r.read_u16_be().unwrap(), 0x1234);
        assert_eq!(r.read_two_bytes().unwrap(), (0xAB, 0xCD));
        assert!(r.is_empty());
    }

    #[test]
    fn test_byte_reader_eof_errors() {
        let data = [0x42];
        let mut r = ByteReader::new(&data);
        assert!(r.read_two_bytes().is_err());
        assert!(r.read_u16_be().is_err());
        assert!(r.read_bytes(2).is_err());
        assert_eq!(r.read_byte().unwrap(), 0x42);
        assert!(r.read_byte().is_err());
    }
}
