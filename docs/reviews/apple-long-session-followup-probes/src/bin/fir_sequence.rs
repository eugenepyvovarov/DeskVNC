#![allow(dead_code)] // Only the FIR builder is needed from the production module.
#[path = "../../../../../crates/apple-core/src/rtcp.rs"]
mod rtcp;

fn main() {
    // This is the exact ownership shape in current session.rs: one sequence
    // object in one FeedbackClock, reused for every target SSRC.
    let mut sequence = rtcp::FirSequence::new(10);
    let first_a = rtcp::full_intra_request(1, 100, sequence.next());
    let first_b = rtcp::full_intra_request(1, 200, sequence.next());
    let second_a = rtcp::full_intra_request(1, 100, sequence.next());
    assert_eq!((first_a[16], first_b[16], second_a[16]), (10, 11, 12));
    assert_ne!(second_a[16], first_a[16].wrapping_add(1));
    println!(
        "A/B/A FIR sequence bytes: {}/{}/{}; A advanced by 2",
        first_a[16], first_b[16], second_a[16]
    );

    let mut sequence = rtcp::FirSequence::new(10);
    let first_a = rtcp::full_intra_request(1, 100, sequence.next());
    for _ in 0..255 {
        rtcp::full_intra_request(1, 200, sequence.next());
    }
    let second_a = rtcp::full_intra_request(1, 100, sequence.next());
    assert_eq!(first_a[16], second_a[16]);
    println!(
        "After 255 intervening B commands, A repeats sequence {}",
        second_a[16]
    );
}
