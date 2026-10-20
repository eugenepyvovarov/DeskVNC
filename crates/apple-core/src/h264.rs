//! H.264 RTP depacketizer (RFC 6184) into Annex-B access units.
//!
//! Single NAL units, STAP-A and FU-A are reassembled. Packets are put back
//! in order before assembly, a packet that was lost invalidates the picture
//! it belonged to instead of turning into a corrupt one, and an access unit
//! is only published when it is complete.
//!
//! Two properties are reported separately, because a decoder cares about
//! them separately:
//!
//! * `keyframe`: the picture can start a decoder on its own. WebCodecs
//!   needs this to accept the chunk.
//! * `reset`: the picture resets the decoder's reference pictures. Only an
//!   IDR does that. An intra picture that is not an IDR is a "starting
//!   picture": independently decodable, but throwing the decoder's
//!   references away would corrupt every picture that follows it, and the
//!   corruption outlives the picture that caused it.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// How many packets may wait for a gap to fill before the wait is given up.
const MAX_REORDER_PACKETS: usize = 64;
/// How many bytes the reorder buffer may hold.
const MAX_REORDER_BYTES: usize = 512 * 1024;
/// How far ahead of the expected sequence number a packet may be and still
/// count as reordered rather than lost.
const MAX_LOOKAHEAD: u16 = 16;
/// The largest hole that is treated as packets lost on the way.
///
/// A picture is tens of packets, so a hole of a thousand is not a loss
/// burst: it is the stream having jumped, which happens when the encoder
/// restarts and starts numbering again. Counting that as loss reported
/// 65573 lost packets on a session that had lost two, and sent a retransmit
/// request for every "missing" packet, which is the storm the rate limits
/// elsewhere exist to prevent.
const MAX_LOSS_GAP: u16 = 1000;
/// How long a packet may wait for the ones before it. A hole that is not
/// filled within this time is a loss, and the picture it belongs to is
/// thrown away rather than left half-assembled.
const REORDER_WAIT: Duration = Duration::from_millis(60);
/// The largest access unit that will be assembled.
const MAX_ACCESS_UNIT_BYTES: usize = 8 * 1024 * 1024;

/// What the depacketizer has seen. Cheap to read, and the only honest way
/// to tell "the picture is fine" from "the picture is broken".
#[derive(Default, Debug, Clone)]
pub struct Stats {
    /// Packets handed to the depacketizer.
    pub packets: u64,
    /// Packets that arrived out of order and were put back.
    pub reordered: u64,
    /// Packets that arrived after their place in the stream had passed.
    pub late: u64,
    /// Times a hole in the sequence numbers was found.
    pub gaps: u64,
    /// Packets missing across all holes.
    pub lost_packets: u64,
    /// The sequence numbers of the packets that went missing, most recent
    /// last. Bounded, because this is a report and not a history.
    pub lost_sequences: Vec<u16>,
    /// Packets that could not be parsed (a truncated aggregation, a length
    /// that does not fit).
    pub malformed: u64,
    /// Access units published.
    pub access_units: u64,
    /// Half-assembled pictures thrown away because a packet was missing.
    pub discarded: u64,
    /// Times the sequence numbers jumped instead of skipping a packet: an
    /// encoder restart or a reset stream, not a network loss.
    pub discontinuities: u64,
}

/// One access unit, ready for the decoder.
pub struct AccessUnit {
    pub annex_b: Vec<u8>,
    /// The picture is independently decodable.
    pub keyframe: bool,
    /// The picture resets the decoder's reference pictures.
    pub reset: bool,
}

#[derive(Default)]
pub struct Depacketizer {
    sps: Vec<u8>,
    pps: Vec<u8>,
    fu: Vec<u8>,
    fu_timestamp: u32,
    fu_open: bool,
    pending: Vec<Vec<u8>>,
    pending_bytes: usize,
    timestamp: Option<u32>,
    /// The next sequence number this stream is expected to carry.
    expected: Option<u16>,
    /// Packets that arrived ahead of their turn.
    reorder: BTreeMap<u16, Packet>,
    reorder_bytes: usize,
    /// When the oldest waiting packet arrived.
    waiting_since: Option<Instant>,
    ready: Vec<AccessUnit>,
    pub stats: Stats,
}

struct Packet {
    timestamp: u32,
    marker: bool,
    payload: Vec<u8>,
    arrived: Instant,
}

impl Depacketizer {
    /// Take one RTP packet and return the access units it completed.
    ///
    /// The sequence number is what makes loss visible. A packet that was
    /// lost leaves a hole, and a picture with a hole in it is thrown away
    /// rather than published half-decoded: a decoder given a picture with a
    /// missing slice does not fail, it quietly paints corruption that lasts
    /// until the next independent picture.
    pub fn push(
        &mut self,
        seq: u16,
        timestamp: u32,
        marker: bool,
        payload: &[u8],
    ) -> Vec<AccessUnit> {
        self.ready.clear();
        self.stats.packets += 1;
        if payload.is_empty() {
            return Vec::new();
        }
        if payload[0] == 0x92 {
            // Apple's configuration packet. It is not part of a picture, and
            // it means the encoder changed: anything half-assembled belongs
            // to the previous parameter sets.
            self.discard_picture();
            self.timestamp = None;
            self.config(payload);
            return Vec::new();
        }
        match self.expected {
            None => {
                self.expected = Some(seq);
                self.assemble(timestamp, marker, payload);
                self.expected = Some(seq.wrapping_add(1));
            }
            Some(expected) => {
                let ahead = seq.wrapping_sub(expected);
                if ahead == 0 {
                    self.assemble(timestamp, marker, payload);
                    self.expected = Some(expected.wrapping_add(1));
                    self.drain();
                } else if ahead > 0x8000 {
                    // Behind the stream: a late packet, or a duplicate of
                    // one already assembled. Either way its place has gone.
                    self.stats.late += 1;
                } else if ahead <= MAX_LOOKAHEAD {
                    // Close enough behind to be reordering rather than loss.
                    self.buffer(seq, timestamp, marker, payload);
                } else if ahead > MAX_LOSS_GAP {
                    // The numbering jumped. That is a restart, not a loss,
                    // so nothing is asked for and nothing is counted as lost
                    // on the way; the picture in hand is dropped because its
                    // references are gone.
                    self.stats.discontinuities += 1;
                    self.discard_picture();
                    self.expected = Some(seq);
                    self.assemble(timestamp, marker, payload);
                    self.expected = Some(seq.wrapping_add(1));
                    self.drain();
                } else {
                    // Too far ahead: the packets in between are lost.
                    self.report_gap(expected, u64::from(ahead - 1));
                    self.expected = Some(seq);
                    self.assemble(timestamp, marker, payload);
                    self.expected = Some(seq.wrapping_add(1));
                    self.drain();
                }
            }
        }
        std::mem::take(&mut self.ready)
    }

    /// Whether a candidate has parameter sets to accompany a starting picture.
    pub(crate) fn has_configuration(&self) -> bool {
        !self.sps.is_empty() && !self.pps.is_empty()
    }

    /// Forget the stream: the next picture starts a new one.
    pub fn reset(&mut self) {
        self.discard_picture();
        self.timestamp = None;
        self.expected = None;
        self.reorder.clear();
        self.reorder_bytes = 0;
        self.waiting_since = None;
    }

    fn buffer(&mut self, seq: u16, timestamp: u32, marker: bool, payload: &[u8]) {
        if self.reorder.len() >= MAX_REORDER_PACKETS
            || self.reorder_bytes + payload.len() > MAX_REORDER_BYTES
        {
            // The buffer is full: the missing packets are not coming. Give
            // up on the hole and carry on with what has arrived.
            self.flush_oldest();
            if self.reorder.len() >= MAX_REORDER_PACKETS
                || self.reorder_bytes + payload.len() > MAX_REORDER_BYTES
            {
                return;
            }
        }
        self.reorder_bytes += payload.len();
        let arrived = Instant::now();
        if self.waiting_since.is_none() {
            self.waiting_since = Some(arrived);
        }
        self.reorder.insert(
            seq,
            Packet {
                timestamp,
                marker,
                payload: payload.to_vec(),
                arrived,
            },
        );
        self.stats.reordered += 1;
    }

    /// Give up on a hole that has not been filled in time.
    ///
    /// Without this a single lost packet would hold the stream still for
    /// ever: the packets behind it would wait for a sequence number that
    /// is never going to arrive. The picture is thrown away and the stream
    /// carries on from the packet that did arrive.
    pub fn flush(&mut self) -> Vec<AccessUnit> {
        self.ready.clear();
        let Some(since) = self.waiting_since else {
            return Vec::new();
        };
        if since.elapsed() < REORDER_WAIT {
            return Vec::new();
        }
        self.flush_oldest();
        std::mem::take(&mut self.ready)
    }

    /// Process the buffered packets that have become consecutive.
    fn drain(&mut self) {
        while let Some(expected) = self.expected {
            let Some(packet) = self.reorder.remove(&expected) else {
                break;
            };
            self.reorder_bytes = self.reorder_bytes.saturating_sub(packet.payload.len());
            self.assemble(packet.timestamp, packet.marker, &packet.payload);
            self.expected = Some(expected.wrapping_add(1));
        }
        if self.reorder.is_empty() {
            self.waiting_since = None;
        } else {
            self.waiting_since = self.reorder.values().map(|p| p.arrived).min();
        }
    }

    /// Abandon the hole and process the oldest buffered packet.
    fn flush_oldest(&mut self) {
        let Some(&seq) = self.reorder.keys().next() else {
            return;
        };
        let expected = self.expected.unwrap_or(seq);
        let skipped = seq.wrapping_sub(expected);
        // A buffered packet that is BEHIND the stream is stale: it waited
        // while the stream moved past it. Wrapping subtraction turns that
        // into a hole of almost the whole sequence space, and counting it as
        // loss reported 196617 lost packets on a stream that had lost a
        // handful, then asked for every one of them. Drop it as late.
        if skipped > MAX_LOSS_GAP {
            if let Some(packet) = self.reorder.remove(&seq) {
                self.reorder_bytes = self.reorder_bytes.saturating_sub(packet.payload.len());
            }
            self.stats.late += 1;
            return;
        }
        // The packet that was waited for is not a loss at all.
        if skipped > 0 {
            self.report_gap(expected, u64::from(skipped));
        }
        let Some(packet) = self.reorder.remove(&seq) else {
            return;
        };
        self.reorder_bytes = self.reorder_bytes.saturating_sub(packet.payload.len());
        self.expected = Some(seq);
        self.assemble(packet.timestamp, packet.marker, &packet.payload);
        self.expected = Some(seq.wrapping_add(1));
        self.drain();
    }

    /// A hole in the sequence numbers. The picture it belongs to can never
    /// be assembled correctly, so it is thrown away.
    fn report_gap(&mut self, from: u16, lost: u64) {
        self.stats.gaps += 1;
        self.stats.lost_packets += lost;
        // Remember which packets went missing, so they can be asked for.
        for i in 0..lost.min(64) {
            self.stats.lost_sequences.push(from.wrapping_add(i as u16));
        }
        if self.stats.lost_sequences.len() > 64 {
            let excess = self.stats.lost_sequences.len() - 64;
            self.stats.lost_sequences.drain(..excess);
        }
        self.discard_picture();
    }

    fn discard_picture(&mut self) {
        if !self.pending.is_empty() || self.fu_open {
            self.stats.discarded += 1;
        }
        self.pending.clear();
        self.pending_bytes = 0;
        self.fu.clear();
        self.fu_open = false;
    }

    fn assemble(&mut self, timestamp: u32, marker: bool, payload: &[u8]) {
        if self.timestamp != Some(timestamp) {
            // A new picture. Anything half-assembled belonged to the old
            // one, including an unfinished fragment: it can never be
            // completed, and it must not suppress the picture that follows.
            self.discard_picture();
            self.timestamp = Some(timestamp);
        }
        let nal_type = payload[0] & 0x1f;
        let nals: Vec<Vec<u8>> = match nal_type {
            1..=23 => vec![payload.to_vec()],
            24 => match stap_a(payload) {
                Ok(nals) => nals,
                Err(()) => {
                    // A truncated aggregation: the picture is broken. No
                    // packet went missing, but the picture is unusable.
                    self.stats.malformed += 1;
                    self.discard_picture();
                    return;
                }
            },
            28 => match self.fu(timestamp, payload) {
                Some(nal) => vec![nal],
                None => Vec::new(),
            },
            _ => return,
        };
        for nal in &nals {
            match nal_type_of(nal) {
                7 => self.sps = nal.clone(),
                8 => self.pps = nal.clone(),
                _ => {}
            }
        }
        for nal in nals {
            self.pending_bytes += nal.len();
            if self.pending_bytes > MAX_ACCESS_UNIT_BYTES {
                self.stats.malformed += 1;
                self.discard_picture();
                return;
            }
            self.pending.push(nal);
        }
        if !marker || self.fu_open || self.pending.is_empty() {
            return;
        }
        let nals = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        let keyframe = is_independent(&nals);
        let reset = nals.iter().any(|n| nal_type_of(n) == 5);
        let mut annex_b = Vec::new();
        if keyframe {
            if !self.sps.is_empty() && !nals.iter().any(|n| nal_type_of(n) == 7) {
                push_nal(&mut annex_b, &self.sps);
            }
            if !self.pps.is_empty() && !nals.iter().any(|n| nal_type_of(n) == 8) {
                push_nal(&mut annex_b, &self.pps);
            }
        }
        for nal in &nals {
            push_nal(&mut annex_b, nal);
        }
        if annex_b.is_empty() {
            return;
        }
        self.stats.access_units += 1;
        self.ready.push(AccessUnit {
            annex_b,
            keyframe,
            reset,
        });
    }

    // Apple's configuration packet contains an ISO BMFF avcC box, not a NAL.
    fn config(&mut self, payload: &[u8]) {
        let Some(at) = payload.windows(4).position(|w| w == b"avcC") else {
            return;
        };
        let Some(data) = payload.get(at + 4..) else {
            return;
        };
        if data.len() < 6 || data[0] != 1 {
            return;
        }
        let mut pos = 6;
        for kind in [7, 8] {
            let count = if kind == 7 {
                data[5] & 31
            } else {
                let Some(&n) = data.get(pos) else { return };
                pos += 1;
                n
            };
            for _ in 0..count {
                let Some(len) = data.get(pos..pos + 2) else {
                    return;
                };
                let len = u16::from_be_bytes([len[0], len[1]]) as usize;
                pos += 2;
                let Some(nal) = data.get(pos..pos + len) else {
                    return;
                };
                pos += len;
                if nal_type_of(nal) == kind {
                    if kind == 7 {
                        self.sps = nal.to_vec();
                    } else {
                        self.pps = nal.to_vec();
                    }
                }
            }
        }
    }

    fn fu(&mut self, timestamp: u32, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < 2 {
            return None;
        }
        let indicator = payload[0];
        let header = payload[1];
        let start = header & 0x80 != 0;
        let end = header & 0x40 != 0;
        let nal_type = header & 0x1f;
        if start {
            self.fu.clear();
            let nal_header = (indicator & 0xe0) | nal_type;
            self.fu.push(nal_header);
            self.fu_timestamp = timestamp;
            self.fu_open = true;
        } else if !self.fu_open || self.fu_timestamp != timestamp {
            // A fragment without its start, or one left over from another
            // picture. Either way it cannot be completed.
            self.fu_open = false;
            self.fu.clear();
            return None;
        }
        self.fu.extend_from_slice(&payload[2..]);
        if end {
            self.fu_open = false;
            Some(std::mem::take(&mut self.fu))
        } else {
            None
        }
    }
}

/// Parse a STAP-A aggregation.
///
/// An aggregation is all or nothing: a NAL whose length runs past the end of
/// the packet means the packet was cut short, and a picture that contains it
/// is broken. Publishing the part that did fit would hand the decoder a
/// picture that is missing a slice, which it does not report as an error.
fn stap_a(payload: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    // Apple inserts a two-byte decoding-order number after the indicator.
    // The plain layout is tried as a fallback, so a server that does not use
    // one is still read.
    stap_a_with_don(payload, true).or_else(|()| stap_a_with_don(payload, false))
}

fn stap_a_with_don(payload: &[u8], with_don: bool) -> Result<Vec<Vec<u8>>, ()> {
    let mut out = Vec::new();
    let mut i = if with_don { 3 } else { 1 };
    while i < payload.len() {
        if i + 2 > payload.len() {
            return Err(());
        }
        let n = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
        i += 2;
        if n == 0 || i + n > payload.len() {
            return Err(());
        }
        let nal = &payload[i..i + n];
        if !is_plausible_nal(nal) {
            return Err(());
        }
        out.push(nal.to_vec());
        i += n;
    }
    if out.is_empty() {
        return Err(());
    }
    Ok(out)
}

/// A NAL inside an aggregation must look like one. Data partition NALs
/// (types 2 to 4) are not used by anything modern and are the usual result
/// of reading a packet at the wrong offset.
fn is_plausible_nal(nal: &[u8]) -> bool {
    if nal.is_empty() || nal[0] & 0x80 != 0 {
        return false;
    }
    matches!(nal[0] & 0x1f, 1 | 5..=13)
}

/// Whether a picture can be decoded on its own.
///
/// An IDR always can. A picture whose slices are all intra can as well: that
/// is the "starting picture" Apple sends at the head of a stream. A picture
/// that mixes an intra slice with an inter slice cannot: the inter slice
/// refers to pictures that are not in the packet.
fn is_independent(nals: &[Vec<u8>]) -> bool {
    if nals.iter().any(|n| nal_type_of(n) == 5) {
        return true;
    }
    let mut saw_slice = false;
    for nal in nals {
        if nal_type_of(nal) == 1 {
            saw_slice = true;
            if !is_intra_slice(nal) {
                return false;
            }
        }
    }
    saw_slice
}

/// Whether a non-IDR slice is an intra slice (I or SI).
fn is_intra_slice(nal: &[u8]) -> bool {
    matches!(slice_type_of(nal), Some(2 | 7))
}

/// The `slice_type` of a slice NAL: the first `ue(v)` is
/// `first_mb_in_slice`, the second is `slice_type`.
fn slice_type_of(nal: &[u8]) -> Option<u32> {
    let mut rbsp = Vec::new();
    let mut zeros = 0;
    for &byte in &nal[1..] {
        if zeros >= 2 && byte == 3 {
            zeros = 0;
            continue;
        }
        rbsp.push(byte);
        zeros = if byte == 0 { zeros + 1 } else { 0 };
    }
    let mut bit = 0;
    let mut ue = || -> Option<u32> {
        let mut leading = 0;
        loop {
            let b = (*rbsp.get(bit / 8)? >> (7 - bit % 8)) & 1;
            bit += 1;
            if b == 1 {
                break;
            }
            leading += 1;
            if leading > 31 {
                return None;
            }
        }
        let mut value = 1u32;
        for _ in 0..leading {
            let b = (*rbsp.get(bit / 8)? >> (7 - bit % 8)) & 1;
            bit += 1;
            value = (value << 1) | u32::from(b);
        }
        Some(value - 1)
    };
    ue()?;
    ue()
}

fn nal_type_of(nal: &[u8]) -> u8 {
    nal.first().map(|b| b & 0x1f).unwrap_or(0)
}

fn push_nal(out: &mut Vec<u8>, nal: &[u8]) {
    out.extend_from_slice(&[0, 0, 0, 1]);
    out.extend_from_slice(nal);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A non-IDR intra slice: first_mb_in_slice = 0, slice_type = 2 (I).
    const INTRA: [u8; 2] = [0x61, 0b1011_0000];
    /// A non-IDR inter slice: first_mb_in_slice = 0, slice_type = 0 (P).
    const INTER: [u8; 2] = [0x61, 0b1100_0000];

    #[test]
    fn fu_a_reassembles_an_idr_and_prepends_parameter_sets() {
        let mut d = Depacketizer::default();
        // The parameter sets arrive in their own packets.
        d.push(1, 1, true, &[0x67, 0x64, 0x00, 0x1f]);
        d.push(2, 1, true, &[0x68, 0xee]);
        // FU-A of a type-5 NAL split in two, marker on the end.
        assert!(d.push(3, 9, false, &[0x7c, 0x85, 0xaa]).is_empty());
        let units = d.push(4, 9, true, &[0x7c, 0x45, 0xbb]);
        assert_eq!(units.len(), 1);
        let au = &units[0];
        assert!(au.keyframe);
        assert!(au.reset, "an IDR resets the decoder");
        assert_eq!(&au.annex_b[..4], &[0, 0, 0, 1]);
        // reconstructed NAL header is 0x65 (IDR) then aa bb
        assert!(au.annex_b.windows(3).any(|w| w == [0x65, 0xaa, 0xbb]));
    }

    #[test]
    fn a_stale_buffered_packet_is_not_counted_as_a_hole() {
        // The reorder buffer fills, and its oldest entry is now behind the
        // stream. Wrapping subtraction reads that as a hole of 65534
        // packets, which is where "196617 lost" came from.
        let mut d = Depacketizer::default();
        d.push(1, 1, true, &[0x61, 0xc0]);
        // Far ahead, so the entries are buffered as reordering.
        for seq in 2..=(MAX_REORDER_PACKETS as u16 + 4) {
            d.push(seq, 2, true, &[0x61, 0xc0]);
        }
        // Now the stream has moved past the early buffered entries.
        d.push(40_000, 3, true, &[0x61, 0xc0]);
        let before = d.stats.lost_packets;
        // Filling the buffer forces flushes of whatever is stale.
        for seq in 40_001..=(40_000 + MAX_REORDER_PACKETS as u16 + 8) {
            d.push(seq, 4, true, &[0x61, 0xc0]);
        }
        assert!(
            d.stats.lost_packets - before < 100,
            "a stale entry was counted as {} lost packets",
            d.stats.lost_packets - before
        );
    }

    #[test]
    fn a_jump_in_the_sequence_numbers_is_a_restart_not_a_loss() {
        // The encoder restarted and began numbering again. Counting the hole
        // as loss reported 65573 lost packets on a session that had lost
        // two, and asked the Mac for every one of them.
        let mut d = Depacketizer::default();
        d.push(100, 1, true, &[0x61, 0xc0]);
        assert_eq!(d.stats.lost_packets, 0);
        d.push(30_000, 2, true, &[0x61, 0xc0]);
        assert_eq!(d.stats.lost_packets, 0, "a jump is not loss");
        assert_eq!(d.stats.discontinuities, 1);
        assert!(d.stats.lost_sequences.is_empty(), "nothing to ask for");
        // A hole inside the stream is still loss, and still asked for: the
        // 28 packets between the expected one and the one that arrived.
        d.push(30_030, 3, true, &[0x61, 0xc0]);
        assert_eq!(d.stats.lost_packets, 28);
        assert_eq!(d.stats.lost_sequences.first(), Some(&30_001));
        assert_eq!(d.stats.lost_sequences.len(), 28);
    }

    #[test]
    fn an_intra_picture_is_a_key_picture_but_does_not_reset_the_decoder() {
        let mut d = Depacketizer::default();
        let units = d.push(1, 5, true, &INTRA);
        assert_eq!(units.len(), 1);
        assert!(units[0].keyframe, "an intra picture can start a decoder");
        assert!(!units[0].reset, "but it must not throw the references away");
    }

    #[test]
    fn a_mixed_intra_and_inter_picture_is_not_independently_decodable() {
        let mut d = Depacketizer::default();
        d.push(1, 7, false, &INTRA);
        let units = d.push(2, 7, true, &INTER);
        assert_eq!(units.len(), 1);
        assert!(
            !units[0].keyframe,
            "a picture with an inter slice needs its references"
        );
        assert!(!units[0].reset);
    }

    #[test]
    fn a_lost_fragment_end_does_not_block_the_next_complete_picture() {
        let mut d = Depacketizer::default();
        // A fragment starts and its end is lost.
        assert!(d.push(1, 100, false, &[0x7c, 0x85, 0xaa]).is_empty());
        // The next picture arrives complete and must be published.
        let units = d.push(2, 200, true, &[0x65, 0xbb, 0xcc]);
        assert_eq!(
            units.len(),
            1,
            "the unfinished fragment suppressed the next picture"
        );
        assert!(units[0].reset);
    }

    #[test]
    fn a_truncated_aggregation_is_not_published_as_a_key_picture() {
        let mut d = Depacketizer::default();
        // STAP-A: one complete NAL, then a NAL whose length runs past the end.
        let packet = [0x78, 0, 0, 0, 2, 0x65, 0xaa, 0, 5, 0xff];
        let units = d.push(1, 3, true, &packet);
        assert!(units.is_empty(), "a broken aggregation was published");
        assert_eq!(d.stats.malformed, 1);
    }

    #[test]
    fn a_lost_middle_fragment_never_reaches_the_decoder() {
        let mut d = Depacketizer::default();
        // Fragment start and end arrive; the middle is lost. The sequence
        // numbers show the hole.
        d.push(10, 100, false, &[0x7c, 0x85, 0xaa]);
        let units = d.push(12, 100, true, &[0x7c, 0x45, 0xcc]);
        assert!(
            units.is_empty(),
            "a picture with a missing slice was published"
        );
        // The hole is only given up on once the wait is over.
        assert_eq!(
            d.stats.gaps, 0,
            "a single hole is not a loss until it has waited"
        );
        std::thread::sleep(REORDER_WAIT + Duration::from_millis(10));
        let units = d.flush();
        assert!(
            units.is_empty(),
            "the broken picture was published after the wait"
        );
        assert_eq!(d.stats.gaps, 1);
        assert_eq!(d.stats.lost_packets, 1);
        assert_eq!(d.stats.discarded, 1);
    }

    #[test]
    fn reordered_packets_are_put_back_in_order() {
        let mut d = Depacketizer::default();
        // Establish the stream's sequence space.
        d.push(100, 90, true, &[0x68, 0xee]);
        // The end of a picture arrives before its start.
        d.push(102, 100, true, &[0x65, 0xbb]);
        let units = d.push(101, 100, false, &[0x67, 0x64, 0x00, 0x1f]);
        assert_eq!(units.len(), 1, "the reordered pair was not reassembled");
        assert!(units[0].keyframe);
        assert_eq!(d.stats.reordered, 1);
        assert_eq!(d.stats.gaps, 0);
    }

    #[test]
    fn a_late_duplicate_is_ignored() {
        let mut d = Depacketizer::default();
        d.push(10, 100, true, &[0x65, 0xbb]);
        assert!(d.push(10, 100, true, &[0x65, 0xbb]).is_empty());
        assert_eq!(d.stats.late, 1);
    }

    #[test]
    fn the_reordered_buffer_is_bounded() {
        let mut d = Depacketizer::default();
        // Fill the buffer with packets that never get their gap filled.
        for i in 1..=(MAX_REORDER_PACKETS as u16 + 8) {
            d.push(1000 + i, 1000 + u32::from(i), false, &[0x61, 0xaa]);
        }
        assert!(
            d.reorder.len() <= MAX_REORDER_PACKETS,
            "the reorder buffer grew past its bound"
        );
    }

    #[test]
    fn a_new_picture_discards_the_previous_one() {
        let mut d = Depacketizer::default();
        d.push(1, 100, false, &INTRA);
        // A new timestamp starts a new picture: the old one is dropped.
        let units = d.push(2, 200, true, &INTER);
        assert_eq!(units.len(), 1);
        assert!(!units[0].keyframe, "an inter slice is not a key picture");
    }
}
