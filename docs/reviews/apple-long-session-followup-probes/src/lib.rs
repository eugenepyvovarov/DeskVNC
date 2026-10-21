// Follow-up characterization probes: passing confirms observed behavior, not a fix.
#![allow(dead_code)] // Imported production modules are only partly exercised here.
#[path = "../../../../crates/apple-core/src/h264.rs"]
mod h264;
#[path = "../../../../crates/apple-core/src/pictures.rs"]
mod pictures;
#[path = "../../../../crates/apple-core/src/rtcp.rs"]
mod rtcp;
#[path = "../../../../crates/apple-core/src/srtp.rs"]
mod srtp;
#[path = "../../../../crates/apple-core/src/video.rs"]
mod video;

#[cfg(test)]
mod followup {
    use super::*;
    use std::time::{Duration, Instant};
    const KEY: [u8; 46] = [0x12; 46];
    fn key_picture(id: u8) -> Vec<u8> {
        let mut p = vec![0x78, 0, 0];
        for nal in [&[0x67, 0x64, 0, 0x34][..], &[0x68, 0xee], &[0x65, 0xb8, id]] {
            p.extend_from_slice(&(nal.len() as u16).to_be_bytes());
            p.extend_from_slice(nal);
        }
        p
    }
    fn packet(ssrc: u32, seq: u16, id: u8) -> Vec<u8> {
        let mut p = vec![0x80, 0x80 | 123];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&u32::from(seq).to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&key_picture(id));
        srtp::SrtpEncryptor::from_blob(&KEY)
            .unwrap()
            .protect(&p)
            .unwrap()
    }
    fn receiver(now: Instant) -> video::VideoStreams {
        video::VideoStreams::new(srtp::SrtpContext::from_blob(&KEY).unwrap(), now)
    }
    #[test]
    fn confirms_eviction_readmits_and_displays_previously_accepted_keyframe_replay() {
        let now = Instant::now();
        let mut rx = receiver(now);
        let old = packet(1, 0, 1);
        assert_eq!(rx.push(&old, 1, now).len(), 1);
        assert!(
            rx.push(&old, 1, now).is_empty(),
            "replay rejected before eviction"
        );
        for id in 2..=33 {
            assert_eq!(
                rx.push(
                    &packet(id, 0, id as u8),
                    u64::from(id),
                    now + Duration::from_millis(u64::from(id))
                )
                .len(),
                1
            );
        }
        assert_eq!(rx.active(), Some(33));
        assert!(rx.evicted() >= 1);
        let units = rx.push(&old, 33, now + Duration::from_secs(2));
        assert_eq!(
            units.len(),
            1,
            "BUG: replay accepted after retirement eviction"
        );
        assert_eq!(units[0].annex_b.last(), Some(&1));
        assert_eq!(
            rx.active(),
            Some(1),
            "BUG: stale replay replaces current display"
        );
    }
    #[test]
    fn confirms_new_generation_allows_unseen_delayed_retired_keyframe_to_replace_healthy_stream() {
        let now = Instant::now();
        let mut rx = receiver(now);
        assert_eq!(rx.push(&packet(10, 0, 10), 1, now).len(), 1);
        let delayed_old = packet(10, 1, 11);
        assert_eq!(
            rx.push(&packet(20, 0, 20), 2, now + Duration::from_millis(10))
                .len(),
            1
        );
        rx.new_epoch();
        let units = rx.push(&delayed_old, 3, now + Duration::from_millis(20));
        assert_eq!(
            units.len(),
            1,
            "BUG: an old in-flight packet claims the new generation"
        );
        assert_eq!(units[0].annex_b.last(), Some(&11));
        assert_eq!(rx.active(), Some(10));
    }
    #[test]
    fn confirms_lost_first_slice_of_new_timestamp_still_publishes_idr_tail() {
        let mut d = h264::Depacketizer::default();
        assert_eq!(d.push(1, 100, true, &[0x65, 0xb8, 1]).len(), 1);
        // seq 2 = first IDR slice of timestamp 200 is lost. seq 3 survives.
        assert!(d.push(3, 200, true, &[0x65, 0xb8, 3]).is_empty());
        std::thread::sleep(Duration::from_millis(70));
        let units = d.flush();
        assert_eq!(d.stats.lost_packets, 1);
        assert_eq!(
            units.len(),
            1,
            "BUG: missing picture head was not remembered"
        );
        assert!(units[0].keyframe);
        assert_eq!(units[0].annex_b.last(), Some(&3));
    }
    #[test]
    fn confirms_all_padding_packet_is_false_loss_in_depacketizer() {
        let mut tx = srtp::SrtpEncryptor::from_blob(&KEY).unwrap();
        let mut rx = srtp::SrtpContext::from_blob(&KEY).unwrap();
        let mut d = h264::Depacketizer::default();
        for (seq, payload, padded) in [
            (1, &[0x65, 0xb8][..], false),
            (2, &[1][..], true),
            (3, &[0x65, 0xb8][..], false),
        ] {
            let mut p = vec![if padded { 0xa0 } else { 0x80 }, 0x80 | 123];
            p.extend_from_slice(&u16::to_be_bytes(seq));
            p.extend_from_slice(&u32::from(seq).to_be_bytes());
            p.extend_from_slice(&10u32.to_be_bytes());
            p.extend_from_slice(payload);
            let rtp = rx.unprotect(&tx.protect(&p).unwrap()).unwrap();
            let units = d.push(rtp.seq, rtp.timestamp, rtp.marker, &rtp.payload);
            if seq == 3 {
                assert!(
                    units.is_empty(),
                    "BUG: third media packet unnecessarily waits for received padding packet"
                );
            }
        }
        std::thread::sleep(Duration::from_millis(70));
        assert_eq!(d.flush().len(), 1);
        assert_eq!(d.stats.lost_sequences, [2]);
    }
    #[test]
    fn confirms_truncated_fu_does_not_mark_whole_timestamp_damaged() {
        let mut d = h264::Depacketizer::default();
        d.push(1, 100, false, &[0x65, 0xb8, 1]);
        d.push(2, 100, false, &[0x7c]);
        let units = d.push(3, 100, true, &[0x65, 0xb8, 3]);
        assert_eq!(
            units.len(),
            1,
            "BUG: malformed slice packet is silently skipped"
        );
        assert!(units[0].keyframe);
        assert_eq!(d.stats.malformed, 0);
    }
}
