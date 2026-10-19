//! The buffer between the video receiver and the shell.
//!
//! The receiver must never stop reading the socket to wait for the shell: a
//! socket that is not read overflows, and an overflow loses packets, and a
//! lost packet corrupts the picture that follows it. So the pictures go
//! through a buffer and a second task hands them over.
//!
//! When the shell cannot keep up, the buffer is full, and then the choice
//! matters:
//!
//! * Keeping the oldest pictures and dropping the newest one leaves the
//!   view showing a picture from the past, and every further picture makes
//!   it older. The session looks like it is working while it shows nothing
//!   new.
//! * Keeping the newest and dropping the oldest shows the freshest picture
//!   the client has, and the price is that the reference chain is broken:
//!   a delta picture refers to pictures that were dropped. The buffer
//!   therefore says when the chain was broken, and the pictures after that
//!   are held back until an independent picture arrives.
//!
//! The second is the honest one: a stale picture that never changes is a
//! frozen screen, and a broken chain that is repaired by the next
//! independent picture is a picture that catches up.

use std::collections::VecDeque;

use crate::h264::AccessUnit;

/// How many pictures may wait for the shell.
pub const PICTURE_QUEUE: usize = 8;

/// A bounded buffer of pictures that keeps the newest ones.
pub struct PictureBuffer {
    queue: VecDeque<AccessUnit>,
    capacity: usize,
    /// The chain was broken by a drop, and the pictures after it cannot be
    /// decoded until an independent picture arrives.
    broken: bool,
    dropped: u64,
}

impl PictureBuffer {
    /// A buffer that holds at most `capacity` pictures.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            capacity: capacity.max(1),
            broken: false,
            dropped: 0,
        }
    }

    /// How many pictures are waiting.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether a picture was dropped to make room.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Whether the chain is broken and an independent picture is awaited.
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// Put one picture in.
    ///
    /// Returns true when a picture had to be dropped to make room, which
    /// means the chain is now broken.
    pub fn push(&mut self, unit: AccessUnit) -> bool {
        let mut dropped = false;
        while self.queue.len() >= self.capacity {
            // The oldest picture goes first. It is the one the shell is
            // least likely to want, and keeping it means the view never
            // catches up.
            self.queue.pop_front();
            self.dropped += 1;
            dropped = true;
        }
        if dropped {
            self.broken = true;
        }
        self.queue.push_back(unit);
        dropped
    }

    /// Take the next picture for the shell.
    ///
    /// A picture that follows a dropped one is held back until an
    /// independent picture arrives: a delta picture that refers to a
    /// picture nobody has is not decodable, and handing it to the decoder
    /// paints corruption that lasts until the next independent picture.
    pub fn pop(&mut self) -> Option<AccessUnit> {
        if self.broken {
            // Look for an independent picture. Everything before it belongs
            // to the chain that was broken.
            let position = self.queue.iter().position(|unit| unit.keyframe);
            match position {
                Some(at) => {
                    let unit = self.queue.remove(at);
                    self.broken = false;
                    return unit;
                }
                None => {
                    // Nothing independent has arrived yet. The pictures in
                    // hand are useless, so they go, and the shell is told
                    // nothing until the chain is whole again.
                    self.dropped += self.queue.len() as u64;
                    self.queue.clear();
                    return None;
                }
            }
        }
        self.queue.pop_front()
    }
}

impl Default for PictureBuffer {
    fn default() -> Self {
        Self::with_capacity(PICTURE_QUEUE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn picture(keyframe: bool) -> AccessUnit {
        AccessUnit {
            annex_b: vec![0; 4],
            keyframe,
            reset: keyframe,
        }
    }

    #[test]
    fn a_picture_that_fits_is_kept() {
        let mut buffer = PictureBuffer::with_capacity(4);
        assert!(!buffer.push(picture(true)));
        assert_eq!(buffer.len(), 1);
        assert!(buffer.pop().is_some());
    }

    #[test]
    fn the_newest_picture_is_kept_when_the_buffer_is_full() {
        // The old behaviour dropped the picture that had just arrived, so
        // the view showed a picture from the past and never caught up.
        let mut buffer = PictureBuffer::with_capacity(2);
        buffer.push(picture(true));
        buffer.push(picture(false));
        assert!(buffer.push(picture(false)));
        // The oldest is gone, the newest two are here.
        assert_eq!(buffer.len(), 2);
        assert!(buffer.is_broken());
        assert_eq!(buffer.dropped(), 1);
    }

    #[test]
    fn a_broken_chain_waits_for_an_independent_picture() {
        let mut buffer = PictureBuffer::with_capacity(2);
        buffer.push(picture(true));
        buffer.push(picture(false));
        buffer.push(picture(false)); // drops one
                                     // Nothing independent is waiting, so the shell is given nothing
                                     // rather than a delta it cannot decode.
        assert!(buffer.pop().is_none());
        assert!(buffer.is_broken());
        // The independent picture arrives: the chain is whole again.
        buffer.push(picture(true));
        let unit = buffer
            .pop()
            .expect("the independent picture is handed over");
        assert!(unit.keyframe);
        assert!(!buffer.is_broken());
    }

    #[test]
    fn a_delta_after_a_drop_is_not_handed_to_the_decoder() {
        let mut buffer = PictureBuffer::with_capacity(2);
        buffer.push(picture(true));
        buffer.push(picture(false));
        buffer.push(picture(false)); // drops the first picture
                                     // The buffer now holds two deltas. Neither can be decoded, and
                                     // handing either over would paint corruption.
        assert!(buffer.pop().is_none());
        assert_eq!(buffer.dropped(), 3);
    }

    #[test]
    fn a_buffer_that_never_overflows_never_breaks_the_chain() {
        let mut buffer = PictureBuffer::with_capacity(8);
        for _ in 0..100 {
            buffer.push(picture(false));
            let unit = buffer.pop().expect("every picture is handed over");
            assert!(!unit.keyframe);
        }
        assert_eq!(buffer.dropped(), 0);
        assert!(!buffer.is_broken());
    }
}
