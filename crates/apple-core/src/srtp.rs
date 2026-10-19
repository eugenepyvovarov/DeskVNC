//! SRTP with AES-256-CM and an 80-bit HMAC-SHA1 tag (RFC 3711).
//!
//! The 46-byte key blob is 32 bytes of master key and 14 bytes of master
//! salt. Labels 0, 1 and 2 derive the SRTP cipher key, auth key and salt.

use aes::Aes256;
use cipher::{BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone)]
pub struct SrtpContext {
    cipher_key: [u8; 32],
    auth_key: [u8; 20],
    salt: [u8; 14],
    roc: u32,
    last_seq: Option<u16>,
}

impl SrtpContext {
    pub fn from_blob(blob: &[u8]) -> Option<Self> {
        if blob.len() != 46 {
            return None;
        }
        let mut master_key = [0u8; 32];
        let mut master_salt = [0u8; 14];
        master_key.copy_from_slice(&blob[..32]);
        master_salt.copy_from_slice(&blob[32..]);
        Some(Self {
            cipher_key: derive(&master_key, &master_salt, 0, 32).try_into().ok()?,
            auth_key: derive(&master_key, &master_salt, 1, 20).try_into().ok()?,
            salt: derive(&master_key, &master_salt, 2, 14).try_into().ok()?,
            roc: 0,
            last_seq: None,
        })
    }

    /// Decrypt an SRTP packet in place's payload and return `(header+payload without tag, marker, seq, timestamp, ssrc, payload)`.
    pub fn unprotect(&mut self, packet: &[u8]) -> Option<Rtp> {
        if packet.len() < 12 + 10 {
            return None;
        }
        let tag_at = packet.len() - 10;
        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let roc = self.roc_for(seq);
        let index = ((roc as u64) << 16) | (seq as u64);
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&self.auth_key).ok()?;
        mac.update(&packet[..tag_at]);
        mac.update(&roc.to_be_bytes());
        // SRTP authenticates with the LEFTMOST 80 bits, not the full SHA-1.
        mac.verify_truncated_left(&packet[tag_at..]).ok()?;

        let header_len = rtp_header_len(packet)?;
        if header_len > tag_at {
            return None;
        }
        let ssrc = u32::from_be_bytes(packet[8..12].try_into().ok()?);
        let mut payload = packet[header_len..tag_at].to_vec();
        let iv = packet_iv(&self.salt, ssrc, index);
        apply_keystream(&self.cipher_key, &iv, &mut payload);
        self.observe(seq);
        Some(Rtp {
            marker: packet[1] & 0x80 != 0,
            payload_type: packet[1] & 0x7f,
            seq,
            timestamp: u32::from_be_bytes(packet[4..8].try_into().ok()?),
            ssrc,
            payload,
        })
    }

    fn roc_for(&self, seq: u16) -> u32 {
        match self.last_seq {
            Some(prev) if prev > 0xc000 && seq < 0x4000 => self.roc.wrapping_add(1),
            _ => self.roc,
        }
    }

    fn observe(&mut self, seq: u16) {
        if let Some(prev) = self.last_seq {
            if prev > 0xc000 && seq < 0x4000 {
                self.roc = self.roc.wrapping_add(1);
            }
        }
        self.last_seq = Some(seq);
    }
}

pub struct Rtp {
    pub marker: bool,
    /// RTP payload type. Kept so a later pass can tell video from RTCP.
    #[allow(dead_code)]
    pub payload_type: u8,
    #[allow(dead_code)]
    pub seq: u16,
    pub timestamp: u32,
    #[allow(dead_code)]
    pub ssrc: u32,
    pub payload: Vec<u8>,
}

fn rtp_header_len(packet: &[u8]) -> Option<usize> {
    let cc = (packet[0] & 0x0f) as usize;
    let mut len = 12 + 4 * cc;
    if packet[0] & 0x10 != 0 {
        if packet.len() < len + 4 {
            return None;
        }
        let ext = u16::from_be_bytes([packet[len + 2], packet[len + 3]]) as usize;
        len += 4 + 4 * ext;
    }
    Some(len)
}

fn derive(master_key: &[u8; 32], master_salt: &[u8; 14], label: u8, out_len: usize) -> Vec<u8> {
    let cipher = Aes256::new(master_key.into());
    let mut x = [0u8; 16];
    x[..14].copy_from_slice(master_salt);
    x[7] ^= label;
    let mut out = Vec::with_capacity(out_len);
    while out.len() < out_len {
        let mut block = cipher::generic_array::GenericArray::clone_from_slice(&x);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
        // Increment the 128-bit counter, big-endian.
        for byte in x.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
    out.truncate(out_len);
    out
}

fn packet_iv(salt: &[u8; 14], ssrc: u32, index: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(salt);
    iv[4] ^= (ssrc >> 24) as u8;
    iv[5] ^= (ssrc >> 16) as u8;
    iv[6] ^= (ssrc >> 8) as u8;
    iv[7] ^= ssrc as u8;
    iv[8] ^= (index >> 40) as u8;
    iv[9] ^= (index >> 32) as u8;
    iv[10] ^= (index >> 24) as u8;
    iv[11] ^= (index >> 16) as u8;
    iv[12] ^= (index >> 8) as u8;
    iv[13] ^= index as u8;
    iv
}

fn apply_keystream(key: &[u8; 32], iv: &[u8; 16], payload: &mut [u8]) {
    let cipher = Aes256::new(key.into());
    let mut counter = *iv;
    let mut offset = 0;
    while offset < payload.len() {
        let mut block = cipher::generic_array::GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut block);
        let n = (payload.len() - offset).min(16);
        for i in 0..n {
            payload[offset + i] ^= block[i];
        }
        offset += n;
        for byte in counter.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_80_bit_tag_and_rejects_tampering() {
        let mut receiver = SrtpContext::from_blob(&[42; 46]).unwrap();
        let mut payload = vec![0x65, 1, 2, 3];
        let iv = packet_iv(&receiver.salt, 7, 1);
        apply_keystream(&receiver.cipher_key, &iv, &mut payload);
        let mut packet = vec![0x80, 0xe4, 0, 1, 0, 0, 0, 9, 0, 0, 0, 7];
        packet.extend(payload);
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&receiver.auth_key).unwrap();
        mac.update(&packet);
        mac.update(&0u32.to_be_bytes());
        packet.extend_from_slice(&mac.finalize().into_bytes()[..10]);
        assert_eq!(receiver.unprotect(&packet).unwrap().payload, [0x65, 1, 2, 3]);
        packet[12] ^= 1;
        assert!(receiver.unprotect(&packet).is_none());
    }

    #[test]
    fn derived_keys_change_with_the_label() {
        let key = [9u8; 32];
        let salt = [4u8; 14];
        let a = derive(&key, &salt, 0, 32);
        let b = derive(&key, &salt, 1, 20);
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 20);
        assert_ne!(&a[..20], b.as_slice());
    }
}
