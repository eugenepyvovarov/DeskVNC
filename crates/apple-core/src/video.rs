//! Single-display AVC stream selection across encoder restarts.
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::h264::{AccessUnit, Depacketizer, Stats};
use crate::srtp::SrtpContext;

const MAX_STREAMS: usize = 32;
const STREAM_STALL: Duration = Duration::from_millis(750);
/// How many replaced streams keep their replay identity.
///
/// A tombstone holds only an SRTP context: the accepted packet index and the
/// replay bitmap. That is what refuses a replayed or delayed packet from an
/// encoder that has been replaced, and it is small enough to keep for many
/// more streams than the assembly table. Forgetting one is a bounded loss of
/// that protection, logged when it happens.
const RETIRED_CAPACITY: usize = 128;

struct Stream {
    srtp: SrtpContext,
    depay: Depacketizer,
    /// When this stream was last seen, for eviction order.
    last_seen: Instant,
}

/// A replaced stream's identity, kept after its assembly state is gone.
struct Retired {
    srtp: SrtpContext,
    last_seen: Instant,
}

pub(crate) struct VideoStreams {
    keys: SrtpContext,
    streams: HashMap<u32, Stream>,
    /// Replaced streams, kept for replay refusal only.
    retired: HashMap<u32, Retired>,
    active: Option<u32>,
    last_picture: Instant,
    active_generation: u64,
    authenticated: u64,
    /// Streams removed to make room for a replacement.
    evicted: u64,
}

impl VideoStreams {
    pub(crate) fn new(keys: SrtpContext, now: Instant) -> Self {
        Self {
            keys,
            streams: HashMap::new(),
            retired: HashMap::new(),
            active: None,
            last_picture: now,
            active_generation: 0,
            authenticated: 0,
            evicted: 0,
        }
    }

    /// Every stream starts a new epoch.
    ///
    /// A re-offer asks the Mac for a new stream. The Mac's encoder may
    /// start its packet numbers again, and a receiver that remembers the
    /// old ones refuses every packet of the new stream as a replay, so the
    /// picture never comes back.
    pub(crate) fn new_epoch(&mut self) {
        // Only the streams that could become the new one are reset. A
        // tombstone keeps its replay window: clearing it would readmit
        // traffic from an encoder that has already been replaced.
        for stream in self.streams.values_mut() {
            stream.srtp.new_epoch();
            stream.depay.reset();
        }
    }

    /// How many stream entries were evicted to make room.
    pub(crate) fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Remove one stream so a replacement can be recorded.
    ///
    /// The active stream is never the victim: its replay window is the one
    /// that protects what is on screen. A retired stream goes before a
    /// candidate, and the one silent for longest goes first within a role.
    /// The alternative was refusing every new SSRC after thirty two had ever
    /// been seen, for the rest of the connection.
    fn evict_one(&mut self) -> bool {
        let victim = self
            .streams
            .iter()
            .filter(|(ssrc, _)| Some(**ssrc) != self.active)
            .min_by_key(|(_, stream)| stream.last_seen)
            .map(|(ssrc, _)| *ssrc);
        let Some(victim) = victim else {
            return false;
        };
        self.streams.remove(&victim);
        self.evicted += 1;
        // Capacity pressure is a health event, not a one-time warning
        // followed by a picture that never comes back. Log doubling counts so
        // a churning table stays visible without a line per replacement.
        if self.evicted.is_power_of_two() {
            tracing::warn!(
                ssrc = victim,
                evictions = self.evicted(),
                limit = MAX_STREAMS,
                "Apple video stream table is churning: replacements evict inactive streams"
            );
        } else {
            tracing::debug!(
                ssrc = victim,
                "Apple video stream evicted for a replacement"
            );
        }
        true
    }

    pub(crate) fn active(&self) -> Option<u32> {
        self.active
    }

    /// Whether the active stream has stopped producing complete pictures.
    pub(crate) fn active_picture_stalled(&self, now: Instant, threshold: Duration) -> bool {
        self.active.is_some() && now.duration_since(self.last_picture) >= threshold
    }

    pub(crate) fn authenticated(&self) -> u64 {
        self.authenticated
    }
    pub(crate) fn active_stats(&self) -> Option<&Stats> {
        self.streams.get(&self.active?).map(|s| &s.depay.stats)
    }

    pub(crate) fn push(&mut self, packet: &[u8], generation: u64, now: Instant) -> Vec<AccessUnit> {
        if packet.len() < 12 || packet[1] & 0x7f != 123 {
            return Vec::new();
        }
        let ssrc = u32::from_be_bytes(packet[8..12].try_into().unwrap());
        if !self.streams.contains_key(&ssrc) {
            if let Some(retired) = self.retired.get_mut(&ssrc) {
                // A packet from an encoder that has been replaced. It is
                // authenticated against that stream's own replay window, so a
                // replay is refused and an unseen delayed packet is consumed,
                // but it is never adopted: a local generation change is not
                // proof that the sender restarted, and the keys did not
                // change. Re-adopting here is how delayed old video took the
                // display back.
                if retired.srtp.unprotect(packet).is_some() {
                    retired.last_seen = now;
                }
                return Vec::new();
            }
        }
        let rtp = if let Some(stream) = self.streams.get_mut(&ssrc) {
            stream.srtp.unprotect(packet)
        } else {
            // Do not allocate a slot, evict streams, or reset replay windows
            // based on an unauthenticated SSRC from the clear RTP header.
            let mut srtp = self.keys.clone();
            let Some(rtp) = srtp.unprotect(packet) else {
                return Vec::new();
            };
            if self.streams.len() >= MAX_STREAMS && !self.evict_one() {
                tracing::warn!("Apple video stream limit reached and nothing could be evicted");
                return Vec::new();
            }
            self.streams.insert(
                ssrc,
                Stream {
                    srtp,
                    depay: Depacketizer::default(),
                    last_seen: now,
                },
            );
            Some(rtp)
        };
        let Some(rtp) = rtp else { return Vec::new() };
        self.authenticated += 1;
        let stream = self.streams.get_mut(&ssrc).unwrap();
        stream.last_seen = now;
        // Assemble candidates too: skipping their early packets discards
        // precisely the SPS/PPS and first key picture needed for a switch.
        let units = stream
            .depay
            .push(rtp.seq, rtp.timestamp, rtp.marker, &rtp.payload);
        self.select(ssrc, units, generation, now)
    }

    /// Move a replaced stream out of the assembly table.
    ///
    /// Its depacketizer goes: the half-assembled picture belongs to a decoder
    /// that is gone. Its SRTP context stays, because it is the only thing
    /// that can tell a replayed packet from that encoder apart from a new
    /// one, and the media keys never changed.
    fn retire(&mut self, ssrc: u32, now: Instant) {
        let Some(stream) = self.streams.remove(&ssrc) else {
            return;
        };
        if self.retired.len() >= RETIRED_CAPACITY {
            let oldest = self
                .retired
                .iter()
                .min_by_key(|(_, retired)| retired.last_seen)
                .map(|(ssrc, _)| *ssrc);
            if let Some(oldest) = oldest {
                self.retired.remove(&oldest);
                tracing::warn!(
                    ssrc = oldest,
                    capacity = RETIRED_CAPACITY,
                    "Apple retired stream identity forgotten at the cap"
                );
            }
        }
        self.retired.insert(
            ssrc,
            Retired {
                srtp: stream.srtp,
                last_seen: now,
            },
        );
    }

    fn select(
        &mut self,
        ssrc: u32,
        mut units: Vec<AccessUnit>,
        generation: u64,
        now: Instant,
    ) -> Vec<AccessUnit> {
        if self.active != Some(ssrc) {
            let may_replace = self.active.is_none()
                || generation != self.active_generation
                || now.duration_since(self.last_picture) > STREAM_STALL;
            if !may_replace || !self.streams[&ssrc].depay.has_configuration() {
                return Vec::new();
            }
            let Some(first) = units.iter().position(|u| u.keyframe) else {
                return Vec::new();
            };
            units.drain(..first);
            // A new SSRC is a new decoder, including Apple's non-IDR intra
            // starting picture. Subsequent intra pictures do not reset it.
            units[0].reset = true;
            let previous = self.active.replace(ssrc);
            if let Some(previous) = previous {
                self.retire(previous, now);
            }
            self.active_generation = generation;
            tracing::info!(
                ssrc,
                ?previous,
                generation,
                "Apple configured video stream adopted"
            );
        }
        if !units.is_empty() {
            self.last_picture = now;
        }
        units
    }

    pub(crate) fn flush(&mut self, generation: u64, now: Instant) -> Vec<AccessUnit> {
        // Candidates can be waiting on the same reorder timeout as the
        // active stream. Flushing only the active one can strand their key
        // picture indefinitely when no more packets arrive.
        let mut ids: Vec<_> = self.streams.keys().copied().collect();
        ids.sort_unstable_by_key(|ssrc| (Some(*ssrc) != self.active, *ssrc));
        let mut output = Vec::new();
        for ssrc in ids {
            let stream = self.streams.get_mut(&ssrc).unwrap();
            let units = stream.depay.flush();
            output.extend(self.select(ssrc, units, generation, now));
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srtp::SrtpEncryptor;

    const KEY: [u8; 46] = [0x12; 46];
    fn receiver() -> VideoStreams {
        VideoStreams::new(SrtpContext::from_blob(&KEY).unwrap(), Instant::now())
    }
    fn packet(ssrc: u32, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x80, 0x80 | 123];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&u32::from(seq).to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(payload);
        SrtpEncryptor::from_blob(&KEY).unwrap().protect(&p).unwrap()
    }
    fn key_picture() -> Vec<u8> {
        let mut stap = vec![0x78, 0, 0]; // Apple STAP-A with DON
        for nal in [&[0x67, 0x64, 0, 0x34][..], &[0x68, 0xee], &[0x65, 0xb8]] {
            stap.extend_from_slice(&(nal.len() as u16).to_be_bytes());
            stap.extend_from_slice(nal);
        }
        stap
    }

    #[test]
    fn an_active_stream_can_be_detected_as_stalled_without_new_packets() {
        let now = Instant::now();
        let mut rx = receiver();
        assert!(!rx.active_picture_stalled(now, Duration::from_secs(2)));
        assert_eq!(rx.push(&packet(10, 0, &key_picture()), 1, now).len(), 1);
        assert!(!rx.active_picture_stalled(now, Duration::from_secs(2)));
        assert!(rx.active_picture_stalled(now + Duration::from_secs(3), Duration::from_secs(2)));
    }

    #[test]
    fn quality_restart_adopts_configured_key_picture_while_old_stream_is_alive() {
        let mut rx = receiver();
        let now = Instant::now();
        assert_eq!(rx.push(&packet(10, 0, &key_picture()), 1, now).len(), 1);
        // Seeing a candidate before re-offer must not permanently block it.
        assert!(rx.push(&packet(20, 0, &[0x61, 0xe0]), 1, now).is_empty());
        let units = rx.push(&packet(20, 1, &key_picture()), 2, now);
        assert_eq!(rx.active(), Some(20));
        assert_eq!(units.len(), 1);
        assert!(
            units[0].reset,
            "a new SSRC must replace the old decoder context"
        );
        assert_eq!(rx.push(&packet(20, 2, &[0x61, 0xe0]), 2, now).len(), 1);
    }

    #[test]
    fn overlapping_streams_do_not_lock_out_recovery_after_the_old_one_stalls() {
        let mut rx = receiver();
        let now = Instant::now();
        rx.push(&packet(10, 0, &key_picture()), 1, now);
        assert!(rx.push(&packet(20, 0, &key_picture()), 1, now).is_empty());
        let units = rx.push(
            &packet(20, 1, &key_picture()),
            1,
            now + Duration::from_secs(1),
        );
        assert_eq!(rx.active(), Some(20));
        assert_eq!(units.len(), 1);
    }

    #[test]
    fn unconfigured_or_delta_candidates_cannot_replace_a_working_picture() {
        let mut rx = receiver();
        let now = Instant::now();
        rx.push(&packet(10, 0, &key_picture()), 1, now);
        assert!(rx.push(&packet(20, 0, &[0x65, 0xb8]), 2, now).is_empty());
        assert!(rx.push(&packet(30, 0, &[0x61, 0xe0]), 2, now).is_empty());
        assert_eq!(rx.active(), Some(10));
    }

    #[test]
    fn delayed_retired_stream_cannot_take_the_picture_back() {
        let mut rx = receiver();
        let now = Instant::now();
        rx.push(&packet(10, 0, &key_picture()), 1, now);
        rx.push(&packet(20, 0, &key_picture()), 2, now);
        assert_eq!(rx.active(), Some(20));
        assert!(rx
            .push(
                &packet(10, 1, &key_picture()),
                2,
                now + Duration::from_secs(2)
            )
            .is_empty());
        assert_eq!(rx.active(), Some(20));
    }

    #[test]
    fn a_new_stream_may_start_its_packet_numbers_again() {
        // The Mac's encoder restarts when the viewer asks for a new
        // stream, and it may number its packets from the beginning again.
        // The keys are the same, so the packets authenticate, but a
        // receiver that remembers the old numbers calls every one of them
        // a replay, and the picture never comes back.
        let mut rx = receiver();
        let now = Instant::now();
        rx.push(&packet(10, 40_000, &key_picture()), 1, now);
        // The new stream numbers from zero again.
        assert!(rx.push(&packet(10, 0, &key_picture()), 2, now).is_empty());
        // The viewer asked for a new stream, so the epoch starts again.
        rx.new_epoch();
        let units = rx.push(&packet(10, 0, &key_picture()), 2, now);
        assert_eq!(
            units.len(),
            1,
            "the picture comes back after a new stream is asked for"
        );
        assert_eq!(rx.active(), Some(10));
    }

    #[test]
    fn a_replayed_packet_is_still_refused_between_epochs() {
        let mut rx = receiver();
        let now = Instant::now();
        let original = packet(10, 5, &key_picture());
        rx.push(&original, 1, now);
        assert!(rx.push(&original, 1, now).is_empty(), "a replay is refused");
        // Without a new stream being asked for, the numbers keep moving
        // forward and an old packet stays refused.
        assert!(rx.push(&original, 1, now).is_empty());
    }

    #[test]
    fn candidate_keeps_parameter_sets_received_before_its_starting_picture() {
        let mut rx = receiver();
        let now = Instant::now();
        rx.push(&packet(10, 0, &key_picture()), 1, now);
        assert!(rx
            .push(&packet(20, 0, &[0x67, 0x64, 0, 0x34]), 2, now)
            .is_empty());
        assert!(rx.push(&packet(20, 1, &[0x68, 0xee]), 2, now).is_empty());
        let units = rx.push(&packet(20, 2, &[0x65, 0xb8]), 2, now);
        assert_eq!(rx.active(), Some(20));
        assert_eq!(units.len(), 1);
        assert!(units[0].annex_b.windows(5).any(|w| w == [0, 0, 0, 1, 0x67]));
        assert!(units[0].annex_b.windows(5).any(|w| w == [0, 0, 0, 1, 0x68]));
    }

    #[test]
    fn multiple_quality_rounds_replace_the_stream_once_per_generation() {
        let mut rx = receiver();
        let now = Instant::now();
        for generation in 1..=4 {
            let ssrc = generation as u32 * 10;
            assert_eq!(
                rx.push(&packet(ssrc, 0, &key_picture()), generation, now)
                    .len(),
                1
            );
            assert_eq!(rx.active(), Some(ssrc));
            // A second concurrent SSRC without a new re-offer must not
            // alternate pictures with the adopted encoder.
            assert!(rx
                .push(&packet(ssrc + 1, 0, &key_picture()), generation, now)
                .is_empty());
            assert_eq!(rx.active(), Some(ssrc));
        }
    }

    #[test]
    fn incomplete_active_packets_do_not_postpone_stall_recovery() {
        let mut rx = receiver();
        let now = Instant::now();
        rx.push(&packet(10, 0, &key_picture()), 1, now);
        // FU start with no end: traffic is not proof of picture progress.
        rx.push(
            &packet(10, 1, &[0x7c, 0x81, 0xaa]),
            1,
            now + Duration::from_secs(1),
        );
        let units = rx.push(
            &packet(20, 0, &key_picture()),
            1,
            now + Duration::from_secs(1),
        );
        assert_eq!(units.len(), 1);
        assert_eq!(rx.active(), Some(20));
    }

    #[test]
    fn full_stream_cache_does_not_reset_an_active_replay_window() {
        let mut rx = receiver();
        let now = Instant::now();
        let original = packet(10, 0, &key_picture());
        rx.push(&original, 1, now);
        for ssrc in 100..100 + MAX_STREAMS as u32 {
            rx.push(&packet(ssrc, 0, &key_picture()), 1, now);
        }
        assert_eq!(rx.streams.len(), MAX_STREAMS);
        assert_eq!(rx.active(), Some(10));
        assert!(rx.push(&original, 1, now).is_empty());
        assert_eq!(rx.push(&packet(10, 1, &[0x61, 0xe0]), 1, now).len(), 1);
    }

    #[test]
    fn an_encoder_replacement_beyond_the_stream_limit_is_adopted() {
        // Entries were never evicted, so after thirty two authenticated
        // SSRCs every later encoder restart was ignored for the rest of the
        // connection.
        let mut rx = receiver();
        let now = Instant::now();
        for generation in 1..=1_000u64 {
            let ssrc = 10_000 + generation as u32;
            rx.new_epoch();
            let units = rx.push(&packet(ssrc, 0, &key_picture()), generation, now);
            assert_eq!(units.len(), 1, "replacement {generation} was ignored");
            assert_eq!(rx.active(), Some(ssrc));
            assert!(
                rx.streams.len() <= MAX_STREAMS,
                "{} stream entries are retained",
                rx.streams.len()
            );
            assert!(
                rx.retired.len() <= RETIRED_CAPACITY,
                "{} retired identities are retained",
                rx.retired.len()
            );
        }
    }

    #[test]
    fn a_replaced_stream_is_never_readopted_without_a_new_identity() {
        // A local re-offer is a request, not proof that the sender restarted.
        // The keys do not change, so a delayed packet from the replaced
        // encoder authenticates. It is consumed and dropped, never adopted.
        let mut rx = receiver();
        let now = Instant::now();
        rx.push(&packet(10, 0, &key_picture()), 1, now);
        rx.push(&packet(20, 0, &key_picture()), 2, now);
        assert_eq!(rx.active(), Some(20));
        rx.new_epoch();
        // An unseen key picture from the replaced encoder.
        let units = rx.push(&packet(10, 1, &key_picture()), 3, now);
        assert!(units.is_empty(), "delayed old video replaced the stream");
        assert_eq!(rx.active(), Some(20));
        // A replayed packet from it is still refused.
        assert!(rx.push(&packet(10, 0, &key_picture()), 3, now).is_empty());
        assert_eq!(rx.active(), Some(20));
    }

    #[test]
    fn a_replayed_packet_stays_refused_after_many_replacements() {
        // Eviction used to remove the replay history with the entry, so an
        // old key picture was accepted again after enough stream churn.
        let mut rx = receiver();
        let now = Instant::now();
        let original = packet(10, 0, &key_picture());
        rx.push(&original, 1, now);
        assert!(rx.push(&original, 1, now).is_empty(), "a replay is refused");
        for generation in 2..=40u64 {
            let ssrc = 100 + generation as u32;
            rx.new_epoch();
            assert_eq!(
                rx.push(&packet(ssrc, 0, &key_picture()), generation, now)
                    .len(),
                1
            );
        }
        assert!(rx.retired.len() <= RETIRED_CAPACITY);
        // Long picture silence also permits replacement, so the replay is
        // offered under exactly those conditions.
        let later = now + Duration::from_secs(5);
        assert!(
            rx.push(&original, 40, later).is_empty(),
            "an old packet came back after the churn"
        );
        assert_eq!(rx.active(), Some(140));
    }

    #[test]
    fn forged_ssrcs_do_not_allocate_or_erase_active_replay_state() {
        let mut rx = receiver();
        let now = Instant::now();
        let original = packet(10, 0, &key_picture());
        rx.push(&original, 1, now);
        for ssrc in 100u32..200 {
            let mut forged = original.clone();
            forged[8..12].copy_from_slice(&ssrc.to_be_bytes());
            assert!(rx.push(&forged, 2, now).is_empty());
        }
        assert_eq!(rx.streams.len(), 1);
        assert!(
            rx.push(&original, 1, now).is_empty(),
            "replay must remain rejected"
        );
        assert_eq!(rx.push(&packet(10, 1, &[0x61, 0xe0]), 1, now).len(), 1);
    }
}
