//! H.264 RTP depacketizer (RFC 6184) into Annex-B access units.
//!
//! Single NAL units, STAP-A and FU-A are reassembled. An IDR is marked so
//! the webview can start its decoder, and a cached SPS/PPS is prepended to
//! that access unit.

#[derive(Default)]
pub struct Depacketizer {
    sps: Vec<u8>,
    pps: Vec<u8>,
    fu: Vec<u8>,
    fu_timestamp: u32,
    fu_open: bool,
    pending: Vec<Vec<u8>>,
    timestamp: Option<u32>,
}

pub struct AccessUnit {
    pub annex_b: Vec<u8>,
    pub keyframe: bool,
}

impl Depacketizer {
    pub fn push(&mut self, timestamp: u32, marker: bool, payload: &[u8]) -> Option<AccessUnit> {
        if payload.is_empty() {
            return None;
        }
        if payload[0] == 0x92 {
            self.fu_open = false;
            self.fu.clear();
            self.pending.clear();
            self.timestamp = None;
            self.config(payload);
            return None;
        }
        if self.timestamp != Some(timestamp) {
            self.pending.clear();
            self.timestamp = Some(timestamp);
        }
        let nal_type = payload[0] & 0x1f;
        let mut nals: Vec<Vec<u8>> = Vec::new();
        match nal_type {
            1..=23 => nals.push(payload.to_vec()),
            24 => nals.extend(stap_a(payload)),
            28 => {
                if let Some(nal) = self.fu(timestamp, payload) {
                    nals.push(nal);
                }
            }
            _ => return None,
        }
        for nal in &nals {
            match nal_type_of(nal) {
                7 => self.sps = nal.clone(),
                8 => self.pps = nal.clone(),
                _ => {}
            }
        }
        self.pending.extend(nals);
        if !marker || self.fu_open || self.pending.is_empty() {
            return None;
        }
        let nals = std::mem::take(&mut self.pending);
        let keyframe = nals.iter().any(|n| is_keyframe(n));
        let mut annex_b = Vec::new();
        if keyframe {
            if !self.sps.is_empty() && nals.iter().all(|n| nal_type_of(n) != 7) {
                push_nal(&mut annex_b, &self.sps);
            }
            if !self.pps.is_empty() && nals.iter().all(|n| nal_type_of(n) != 8) {
                push_nal(&mut annex_b, &self.pps);
            }
        }
        for nal in &nals {
            push_nal(&mut annex_b, nal);
        }
        if annex_b.is_empty() {
            None
        } else {
            Some(AccessUnit { annex_b, keyframe })
        }
    }

    // Apple's configuration packet contains an ISO BMFF avcC box, not a NAL.
    fn config(&mut self, payload: &[u8]) {
        let Some(at) = payload.windows(4).position(|w| w == b"avcC") else { return };
        let Some(data) = payload.get(at + 4..) else { return };
        if data.len() < 6 || data[0] != 1 { return; }
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
                let Some(len) = data.get(pos..pos + 2) else { return };
                let len = u16::from_be_bytes([len[0], len[1]]) as usize;
                pos += 2;
                let Some(nal) = data.get(pos..pos + len) else { return };
                pos += len;
                if nal_type_of(nal) == kind {
                    if kind == 7 { self.sps = nal.to_vec(); }
                    else { self.pps = nal.to_vec(); }
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

fn stap_a(payload: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    // Apple inserts a two-byte decoding-order number after the indicator.
    let mut i = 3;
    while i + 2 <= payload.len() {
        let n = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
        i += 2;
        if i + n > payload.len() {
            break;
        }
        out.push(payload[i..i + n].to_vec());
        i += n;
    }
    out
}

// Apple also starts streams with non-IDR I slices. WebCodecs still needs
// these marked as key chunks, with their parameter sets in-band.
fn is_keyframe(nal: &[u8]) -> bool {
    match nal_type_of(nal) {
        5 => true,
        1 => {
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
                    if b == 1 { break; }
                    leading += 1;
                    if leading > 31 { return None; }
                }
                let mut value = 1u32;
                for _ in 0..leading {
                    value = (value << 1) | u32::from((*rbsp.get(bit / 8)? >> (7 - bit % 8)) & 1);
                    bit += 1;
                }
                Some(value - 1)
            };
            ue().is_some() && matches!(ue(), Some(2 | 7))
        }
        _ => false,
    }
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

    #[test]
    fn non_idr_i_slice_is_a_starting_picture() {
        // first_mb=0 (1), slice_type=2 (011).
        assert!(is_keyframe(&[0x61, 0b1011_0000]));
        assert!(!is_keyframe(&[0x61, 0b1100_0000]));
        assert!(!is_keyframe(&[0x61]));
    }

    #[test]
    fn fu_a_reassembles_an_idr_and_prepends_parameter_sets() {
        let mut d = Depacketizer::default();
        d.push(1, true, &[0x67, 0x64, 0x00, 0x1f]).unwrap();
        d.push(1, true, &[0x68, 0xee]).unwrap();
        // FU-A of a type-5 NAL split in two, marker on the end.
        assert!(d.push(9, false, &[0x7c, 0x85, 0xaa]).is_none());
        let au = d.push(9, true, &[0x7c, 0x45, 0xbb]).unwrap();
        assert!(au.keyframe);
        assert_eq!(&au.annex_b[..4], &[0, 0, 0, 1]);
        assert!(au.annex_b.windows(4).any(|w| w == [0, 0, 0, 1]));
        // reconstructed NAL header is 0x65 (IDR) then aa bb
        assert!(au.annex_b.windows(3).any(|w| w == [0x65, 0xaa, 0xbb]));
    }
}
