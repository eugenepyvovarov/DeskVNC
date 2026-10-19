// Review-only probes loading the unchanged implementation from the worktree.
#[path = "../../../../crates/apple-core/src/h264.rs"]
mod h264;
#[path = "../../../../crates/apple-core/src/srtp.rs"]
mod srtp;

#[cfg(test)]
mod review {
    use super::*;
    use aes::Aes256;
    use cipher::{BlockEncrypt, KeyInit};
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    #[test]
    fn lost_fu_end_must_not_block_next_complete_idr() {
        let mut d = h264::Depacketizer::default();
        assert!(d.push(1, false, &[0x7c, 0x85, 0xaa]).is_none());
        // The FU end is lost. A complete single-packet IDR arrives at a new
        // timestamp; this must allow recovery rather than inherit fu_open.
        assert!(d.push(2, true, &[0x65, 0xbb, 0xcc]).is_some(),
            "unfinished FU from the old timestamp blocks a new complete IDR");
    }

    #[test]
    fn malformed_aggregation_must_not_publish_partial_key_picture() {
        let mut d = h264::Depacketizer::default();
        // Apple STAP-A: indicator + DON + one complete NAL, then a truncated NAL.
        let packet = [0x78, 0, 0, 0, 2, 0x65, 0xaa, 0, 5, 0xff];
        assert!(d.push(1, true, &packet).is_none(),
            "truncated aggregation is accepted as an independently decodable key picture");
    }

    #[test]
    fn mixed_i_and_p_slices_are_not_an_independent_key_picture() {
        let mut d = h264::Depacketizer::default();
        d.push(1, false, &[0x61, 0xb0]); // first_mb=0, I slice_type=2
        let au = d.push(1, true, &[0x61, 0xc0]).unwrap(); // P slice_type=0
        assert!(!au.keyframe, "any one I slice currently labels the whole mixed picture a key");
    }

    #[test]
    fn transport_loss_is_not_reported_to_the_fu_assembler() {
        let mut d = h264::Depacketizer::default();
        // Original RTP sequence: 10(start aa), 11(middle bb), 12(end cc).
        // Packet 11 was lost. The driver drops seq and passes only timestamp,
        // marker and payload, so the corrupted reference picture is emitted.
        let received = [(10u16, false, vec![0x7c, 0x85, 0xaa]),
                        (12u16, true, vec![0x7c, 0x45, 0xcc])];
        let mut emitted = None;
        for (_seq, marker, payload) in received {
            emitted = d.push(100, marker, &payload).or(emitted);
        }
        assert!(emitted.is_none(), "missing middle fragment reaches the decoder instead of requesting recovery");
    }

    fn derive(label: u8, len: usize) -> Vec<u8> {
        let aes = Aes256::new((&[42u8; 32]).into());
        let mut iv = [0u8; 16];
        iv[..14].fill(42);
        iv[7] ^= label;
        let mut result = Vec::new();
        while result.len() < len {
            let mut block = cipher::generic_array::GenericArray::from(iv);
            aes.encrypt_block(&mut block);
            result.extend(block.as_slice());
            for b in iv.iter_mut().rev() { *b = b.wrapping_add(1); if *b != 0 { break; } }
        }
        result.truncate(len);
        result
    }

    fn packet(seq: u16, roc: u32) -> Vec<u8> {
        // Authentication alone suffices for the replay/ROC tests; payload's
        // encrypted byte is arbitrary and carries no real desktop content.
        let mut p = vec![0x80, 123, (seq >> 8) as u8, seq as u8, 0, 0, 0, 1, 0, 0, 0, 7, 0x55];
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&derive(1, 20)).unwrap();
        mac.update(&p); mac.update(&roc.to_be_bytes());
        p.extend_from_slice(&mac.finalize().into_bytes()[..10]); p
    }

    #[test]
    fn srtp_must_reject_authenticated_replay() {
        let mut receiver = srtp::SrtpContext::from_blob(&[42; 46]).unwrap();
        let p = packet(100, 0);
        assert!(receiver.unprotect(&p).is_some());
        assert!(receiver.unprotect(&p).is_none(), "duplicate authenticated RTP is replayed into media reassembly");
    }

    #[test]
    fn rollover_must_allow_unseen_late_packet_from_previous_cycle() {
        let mut receiver = srtp::SrtpContext::from_blob(&[42; 46]).unwrap();
        assert!(receiver.unprotect(&packet(65534, 0)).is_some());
        assert!(receiver.unprotect(&packet(0, 1)).is_some());
        assert!(receiver.unprotect(&packet(65535, 0)).is_some(),
            "valid out-of-order packet from the previous rollover cycle is rejected");
    }

    #[test]
    fn old_replay_must_not_poison_the_rollover_counter() {
        let mut receiver = srtp::SrtpContext::from_blob(&[42; 46]).unwrap();
        let old = packet(20000, 0);
        assert!(receiver.unprotect(&old).is_some());
        assert!(receiver.unprotect(&packet(65534, 0)).is_some());
        let _ = receiver.unprotect(&old); // must not lower the high-water mark
        assert!(receiver.unprotect(&packet(0, 1)).is_some(),
            "an old authenticated packet rewinds last_seq and the next real rollover cannot authenticate");
    }
}
