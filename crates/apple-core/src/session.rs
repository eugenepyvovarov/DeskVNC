//! One Apple Screen Sharing session.
//!
//! Cleartext through authentication and the prelude, then the record layer.
//! Video is H.264 over SRTP on UDP. Access units are handed to the shell as
//! `RectPayload::H264` for the webview's hardware decoder.

use std::time::{Duration, Instant};

use rand::Rng;
use remote_core::{
    emit, emit_state, ClientCommand, ConnectOptions, CredentialKind, CredentialRequest,
    DecodedRect, Rect, RectPayload, SessionEvent, SessionState,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::auth::{self, SrpSecret};
use crate::h264::Depacketizer;
use crate::record::{self, RecordLayer};
use crate::srtp::{SrtcpEncryptor, SrtpContext};

/// How many distinct video streams are remembered at once. A resized canvas
/// or a new quality tier brings a new SSRC; the old ones are dropped.
const MAX_STREAMS: usize = 32;

/// How long the shown stream may be silent before another stream is taken
/// to be the live one.
const STREAM_STALL: Duration = Duration::from_millis(750);

/// How long a resize round may take before the session gives up on it and
/// says so.
const RESIZE_TIMEOUT: Duration = Duration::from_secs(8);

/// What the user is holding down on the remote machine.
#[derive(Default)]
struct Held {
    /// Keys that were pressed and not released.
    keys: std::collections::BTreeSet<u32>,
    /// The last pointer position and button mask sent.
    pointer: Option<(u16, u16, u16)>,
}

/// Let go of every key and button that is held.
///
/// The remote machine is told about a key going down when it happens and
/// about it coming up when it happens. If the viewer's attention goes
/// elsewhere in between, the key stays down on the remote machine, and the
/// only way to release it is to say so.
async fn release_all(session: &mut Live, held: &mut Held) -> Result<(), SessionError> {
    if let Some((x, y, _)) = held.pointer.take() {
        let body = crate::input::pointer(session.layer.wrap_key(), x, y, 0);
        session.send_body(&body).await?;
    }
    let keys: Vec<u32> = held.keys.iter().copied().collect();
    held.keys.clear();
    for keysym in keys {
        let mut body = [0u8; 8];
        body[0] = 4;
        body[1] = 0; // key up
        body[4..8].copy_from_slice(&keysym.to_be_bytes());
        session.send_body(&body).await?;
    }
    Ok(())
}

/// Ask the Mac for a fresh independent picture.
///
/// The request goes out on the control socket, which is where the Mac's
/// RTCP arrives. Three forms are sent together: the modern request, the
/// picture loss indication, and the legacy request the native viewer uses.
/// Apple's server answers whichever it honours first, and it often ignores
/// the newer ones.
///
/// Requests are rate limited. A burst of loss would otherwise turn into a
/// burst of requests, which the Mac answers with a burst of full pictures.
async fn request_keyframe(
    feedback: &mut Option<SrtcpEncryptor>,
    sender: u32,
    media: u32,
    ctrl: Option<&UdpSocket>,
    ctrl_dest: &str,
    last: &mut Instant,
) {
    // Requests are rate limited. A burst of loss would otherwise turn into
    // a burst of requests, which the Mac answers with a burst of full
    // pictures.
    if last.elapsed() < KEYFRAME_REQUEST_INTERVAL {
        return;
    }
    *last = Instant::now();
    let Some(encryptor) = feedback.as_mut() else { return };
    let Some(socket) = ctrl else { return };
    let packet = crate::rtcp::compound(
        sender,
        &[
            crate::rtcp::full_intra_request(sender, media, 0),
            crate::rtcp::picture_loss_indication(sender, media),
            crate::rtcp::legacy_intra_request(media),
        ]
        .concat(),
    );
    let Some(protected) = encryptor.protect(&packet) else { return };
    if socket.send_to(&protected, ctrl_dest).await.is_err() {
        tracing::warn!("the keyframe request could not be sent");
    } else {
        tracing::info!(media, "asked the Mac for a fresh picture");
    }
}

/// Ask the Mac to send the packets that went missing again.
async fn request_retransmission(
    feedback: &mut Option<SrtcpEncryptor>,
    sender: u32,
    media: u32,
    missing: &[u16],
    ctrl: Option<&UdpSocket>,
    ctrl_dest: &str,
) {
    if missing.is_empty() {
        return;
    }
    let Some(encryptor) = feedback.as_mut() else { return };
    let Some(socket) = ctrl else { return };
    let nack = crate::rtcp::generic_nack(sender, media, missing);
    if nack.is_empty() {
        return;
    }
    let packet = crate::rtcp::compound(sender, &nack);
    let Some(protected) = encryptor.protect(&packet) else { return };
    if socket.send_to(&protected, ctrl_dest).await.is_err() {
        tracing::warn!("the retransmission request could not be sent");
    } else {
        tracing::info!(packets = missing.len(), "asked the Mac for the missing packets");
    }
}

/// Who the media is expected to come from.
///
/// The Mac sends its video and its feedback from a known address. A
/// datagram from anywhere else is not part of the session, and reading one
/// as video would put rubbish into the decoder.
struct Peer {
    addresses: Vec<std::net::IpAddr>,
    port: u16,
}

impl Peer {
    async fn resolve(host: &str, port: u16) -> Self {
        let addresses = match tokio::net::lookup_host((host, port)).await {
            Ok(list) => list.map(|addr| addr.ip()).collect(),
            Err(error) => {
                tracing::warn!(%error, host, "the Mac's address could not be resolved; packets from any address will be read");
                Vec::new()
            }
        };
        Self { addresses, port }
    }

    fn matches(&self, from: &std::net::SocketAddr) -> bool {
        if self.addresses.is_empty() {
            return true; // nothing to check against
        }
        if !self.addresses.contains(&from.ip()) {
            return false;
        }
        // The port is checked and reported rather than enforced: the Mac has
        // been seen to answer from the matching port, but a NAT or a
        // firewall in between may change it, and dropping the media over
        // that would be worse than reading it.
        if from.port() != self.port {
            tracing::debug!(port = from.port(), expected = self.port, "the media came from another port");
        }
        true
    }
}

/// How many assembled pictures may wait for the shell.
///
/// The receiver must never stop reading the socket to wait for the shell:
/// a socket that is not read overflows, and an overflow loses packets, and
/// a lost packet corrupts the picture that follows it. So the pictures go
/// into a queue and a second task hands them over. When the queue is full
/// the oldest picture is dropped and a fresh one is asked for, because a
/// decoder that misses a picture needs an independent one to recover.
const PICTURE_QUEUE: usize = 8;

/// How many times the offer is asked again when the Mac answers with an
/// empty canvas. The Mac does that while its encoder is warming up, and
/// the answer that follows is the one that counts.
const MAX_OFFER_ATTEMPTS: u32 = 3;

/// How often a fresh picture may be asked for.
const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_millis(500);

/// A resize round.
///
/// A round is: ask the Mac for a size, get the layout that answers it, let
/// the encoder restart, and see a picture at the new size. It is not over
/// when the Mac answers, because the encoder restarts after the answer and a
/// second request sent into that restart races it.
///
/// The newest request always wins. A request that arrives while a round is
/// running is remembered and sent when the round ends, even when it asks
/// for the size the session had before the round started: that is a real
/// request, and dropping it is how a quality change used to disappear.
#[derive(Default)]
struct ResizeRound {
    /// The newest size the user asked for.
    requested: Option<(u16, u16)>,
    /// The size the request that is running asked for.
    sent: Option<(u16, u16)>,
    /// The size the server confirmed in the layout that answered it.
    confirmed: Option<(u16, u16)>,
    /// A request is with the server.
    in_flight: bool,
    /// When the request was sent.
    sent_at: Option<Instant>,
    /// The round has to wait for a picture at the new size before it ends.
    /// A layout that did not change the geometry needs no new picture.
    needs_picture: bool,
    /// The request has been sent and the layout that answers it has not
    /// arrived yet. A picture from the old encoder says nothing about the
    /// new size, so the round waits for the layout first.
    awaiting_layout: bool,
}

/// What asking for a size means.
#[derive(Debug, PartialEq, Eq)]
enum ResizeAction {
    /// The picture is already that size. Nothing to ask for.
    Nothing,
    /// Send the request now.
    Send((u16, u16)),
    /// A round is running. The request goes out when that round ends.
    Wait,
}

/// Decide what an ask for a size means, and record it.
fn plan_resize(round: &mut ResizeRound, target: (u16, u16), current: (u16, u16)) -> ResizeAction {
    round.requested = Some(target);
    if round.in_flight {
        // A round is running. The request goes out when it finishes, even
        // when it asks for the size the session had before the round
        // started: it is a real request, and dropping it is how a quality
        // change used to disappear.
        return ResizeAction::Wait;
    }
    if target == current {
        round.requested = None;
        return ResizeAction::Nothing;
    }
    round.sent = Some(target);
    round.sent_at = Some(Instant::now());
    round.in_flight = true;
    round.needs_picture = true;
    round.awaiting_layout = true;
    ResizeAction::Send(target)
}

/// What the end of a round means.
#[derive(Debug, PartialEq, Eq)]
enum RoundEnd {
    /// The round is over. The pair is the size that was asked for and the
    /// size the server chose, when they differ.
    Done(Option<((u16, u16), (u16, u16))>),
    /// Another request goes out, because a newer one arrived while this
    /// round was running.
    Send((u16, u16)),
}

/// Close a round that has been answered and has produced its picture.
fn finish_round(round: &mut ResizeRound) -> RoundEnd {
    round.in_flight = false;
    round.sent_at = None;
    let sent = round.sent;
    match round.requested {
        Some(target) if Some(target) != sent => {
            // A newer request arrived while this round was running. It wins.
            round.sent = Some(target);
            round.sent_at = Some(Instant::now());
            round.in_flight = true;
            round.needs_picture = true;
            round.awaiting_layout = true;
            RoundEnd::Send(target)
        }
        _ => {
            round.requested = None;
            let clamped = match (sent, round.confirmed) {
                (Some(sent), Some(confirmed)) if sent != confirmed => Some((sent, confirmed)),
                _ => None,
            };
            RoundEnd::Done(clamped)
        }
    }
}

/// Ask for a size, or remember the ask until the running round is over.
async fn request_resize(
    session: &mut Live,
    round: &mut ResizeRound,
    target: (u16, u16),
    current: (u16, u16),
    baseline: (u16, u16),
) -> Result<(), SessionError> {
    match plan_resize(round, target, current) {
        ResizeAction::Nothing => Ok(()),
        ResizeAction::Wait => {
            tracing::debug!(w = target.0, h = target.1, "Apple resize request queued");
            Ok(())
        }
        ResizeAction::Send((w, h)) => {
            let (lw, lh) = (session.logical_width, session.logical_height);
            session.send_body(&display_config(w, h, lw, lh, baseline.0, baseline.1)).await?;
            tracing::info!(w, h, "Apple display resize requested");
            Ok(())
        }
    }
}

/// The counters the video receiver keeps and the control loop reads.
///
/// The receiver and the control loop are different tasks, and the numbers
/// are about the media: how many pictures have been decoded, how many
/// packets went missing, and how many times the picture was asked for
/// again.
#[derive(Default)]
struct MediaCounters {
    pictures: std::sync::atomic::AtomicU64,
    lost: std::sync::atomic::AtomicU64,
    recoveries: std::sync::atomic::AtomicU64,
}

/// One video stream: its own SRTP state and its own assembler.
struct Stream {
    srtp: SrtpContext,
    depay: Depacketizer,
}

impl Stream {
    fn new(keys: &SrtpContext) -> Self {
        Self {
            srtp: keys.clone(),
            depay: Depacketizer::default(),
        }
    }
}

/// Send assembled pictures to the shell. Returns false when the shell has
/// gone, which ends the session.
async fn publish(
    events: &mpsc::Sender<SessionEvent>,
    units: Vec<crate::h264::AccessUnit>,
    dimensions: &std::sync::atomic::AtomicU32,
    pictures: &mut u32,
) -> bool {
    for au in units {
        *pictures += 1;
        if *pictures <= 5 || (*pictures <= 60 && au.keyframe) {
            tracing::info!(pictures = *pictures, bytes = au.annex_b.len(), keyframe = au.keyframe, "Apple H.264 picture");
        }
        let size = dimensions.load(std::sync::atomic::Ordering::Relaxed);
        let rect = DecodedRect {
            rect: Rect::new(0, 0, (size >> 16) as u16, size as u16),
            payload: RectPayload::H264 {
                data: au.annex_b,
                flags: 0,
                context_id: 0,
                // `reset` rebuilds the decoder and throws its reference
                // pictures away. Only an IDR may do that: an intra picture
                // that is not an IDR is fed to the existing decoder instead,
                // because wiping the references corrupts every picture that
                // follows it, and the corruption outlives the picture that
                // caused it.
                reset: au.reset,
                keyframe: au.keyframe,
            },
        };
        if emit(
            events,
            SessionEvent::FramebufferUpdate {
                damage: rect.rect,
                rects: vec![rect],
            },
        )
        .await
        .is_err()
        {
            return false;
        }
    }
    true
}

pub async fn run(
    options: ConnectOptions,
    events: mpsc::Sender<SessionEvent>,
    mut commands: mpsc::Receiver<ClientCommand>,
    cancel: tokio_util::sync::CancellationToken,
    host_keys: Option<crate::macos::Verifier>,
) {
    let mut credentials = (
        options.credentials.username.clone().unwrap_or_default(),
        options.credentials.password.clone().unwrap_or_default(),
    );
    let (mut username, mut password) = (credentials.0.clone(), credentials.1.clone());
    if username.is_empty() || password.is_empty() {
        let _ = emit(
            &events,
            SessionEvent::CredentialsRequired(CredentialRequest {
                method: "Apple Screen Sharing".into(),
                kind: CredentialKind::UsernameAndPassword,
                attempt: 1,
                error: None,
                truncates_password: false,
                username_hint: options.credentials.username.clone(),
            }),
        )
        .await;
        match wait_credentials(&mut commands, &cancel).await {
            Some((user, pass)) => {
                if !user.is_empty() {
                    username = user;
                }
                password = pass;
            }
            None => {
                let _ = fail(&events, "sign-in was cancelled").await;
                return;
            }
        }
    }
    let (width, height, ports) = match &options.protocol {
        remote_core::ProtocolOptions::Apple(o) => (o.width, o.height, (o.video_port, o.control_port)),
        _ => (1920, 1080, (5901, 5900)),
    };
    // The session is supervised. A connection that ends is not the end of
    // the session: the driver tries again, and the person watching sees a
    // reconnect rather than a dead pane. The wait between attempts grows,
    // and "Reconnect now" makes it immediate.
    let mut attempt = 0u32;
    // Set when the session is asked to reconnect. The connection ends and
    // the supervisor starts a new one at once, with no wait.
    let reconnect = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let result = connect(
            &options.host,
            options.port,
            &username,
            &password,
            width,
            height,
            ports,
            &events,
            &mut commands,
            &cancel,
            host_keys.clone(),
            &reconnect,
        )
        .await;
        let reason = match result {
            Ok(()) => {
                if !reconnect.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    // The session ended on request. Nothing to retry.
                    return;
                }
                // The session was asked to reconnect. Start a new one at
                // once, with no wait and no failure to report.
                attempt = 0;
                username = credentials.0.clone();
                password = credentials.1.clone();
                continue;
            }
            Err(err) => err.to_string(),
        };
        if cancel.is_cancelled() {
            break;
        }
        let _ = fail(&events, &reason).await;
        let wait = Duration::from_millis(500u64 << attempt.min(4));
        attempt = attempt.saturating_add(1);
        let _ = emit_state(
            &events,
            SessionState::Reconnecting {
                attempt,
                next_retry_ms: wait.as_millis() as u64,
                reason: reason.clone(),
            },
        )
        .await;
        if wait_for_retry(&mut commands, &cancel, wait, &mut credentials).await {
            // The session was asked to stop.
            return;
        }
        // A new attempt starts from a clean slate: the session is a new
        // one, and the old backoff does not apply to it.
        attempt = 0;
        username = credentials.0.clone();
        password = credentials.1.clone();
    }
}

/// Wait before the next attempt. Returns true when the session should end.
async fn wait_for_retry(
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &tokio_util::sync::CancellationToken,
    wait: Duration,
    credentials: &mut (String, String),
) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        tokio::select! {
            _ = cancel.cancelled() => return true,
            cmd = commands.recv() => match cmd {
                None | Some(ClientCommand::Disconnect) => return true,
                Some(ClientCommand::ReconnectNow) => return false,
                Some(ClientCommand::ProvideCredentials { username: user, password: pass, .. }) => {
                    // A new password is for the next attempt.
                    if let Some(user) = user {
                        if !user.is_empty() {
                            credentials.0 = user;
                        }
                    }
                    if !pass.is_empty() {
                        credentials.1 = pass;
                    }
                }
                _ => {}
            },
            _ = tokio::time::sleep(remaining) => return false,
        }
    }
}

async fn wait_credentials(
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &tokio_util::sync::CancellationToken,
) -> Option<(String, String)> {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return None,
            cmd = commands.recv() => match cmd? {
                ClientCommand::ProvideCredentials { username, password, .. } => {
                    return Some((username.unwrap_or_default(), password));
                }
                ClientCommand::CancelCredentials | ClientCommand::Disconnect => return None,
                _ => {}
            }
        }
    }
}

async fn fail(events: &mpsc::Sender<SessionEvent>, reason: &str) -> Result<(), remote_core::EventSinkClosed> {
    emit_state(
        events,
        SessionState::Disconnected {
            reason: reason.to_string(),
            can_retry: true,
            symbol: None,
        },
    )
    .await
}

async fn connect(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    _width: u16,
    _height: u16,
    ports: (u16, u16),
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &tokio_util::sync::CancellationToken,
    host_keys: Option<crate::macos::Verifier>,
    reconnect: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), SessionError> {
    emit_state(events, SessionState::Connecting).await.ok();
    let mut tcp = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect((host, port)))
        .await
        .map_err(|_| SessionError::new("timed out connecting"))?
        .map_err(|e| SessionError::new(e.to_string()))?;
    tcp.set_nodelay(true).ok();

    let banner = read_handshake(&mut tcp, 12).await?;
    if &banner != b"RFB 003.889\n" {
        return Err(SessionError::new("the server did not offer Apple Screen Sharing"));
    }
    tcp.write_all(b"RFB 003.889\n").await?;
    let count = read_handshake(&mut tcp, 1).await?[0] as usize;
    if count == 0 {
        return Err(SessionError::new("the server refused the connection"));
    }
    let types = read_handshake(&mut tcp, count).await?;
    if !types.contains(&33) {
        return Err(SessionError::new("the server has no RSA-SRP sign-in"));
    }

    emit_state(
        events,
        SessionState::Authenticating {
            method: "apple-srp".into(),
        },
    )
    .await
    .ok();

    // Security type 33, then the empty RSA1 packet that asks for the key.
    let mut hello = vec![0x21];
    hello.extend(auth::rsa1_packet(0, 0, &[], 0));
    tcp.write_all(&hello).await?;
    let der = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_rsa_key(&mut tcp))
        .await
        .map_err(|_| SessionError::new("the Mac stopped answering during the sign-in"))??;
    let identity = auth::seal_identity(&der, username)?;
    tcp.write_all(&auth::rsa1_packet(2, 0x0100, &identity, 384)).await?;

    let challenge_buf = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_counted(&mut tcp))
        .await
        .map_err(|_| SessionError::new("the Mac stopped answering during the sign-in"))??;
    let challenge = auth::parse_challenge(&challenge_buf[4..])?;
    let secret = SrpSecret::client(
        password,
        &challenge.salt,
        challenge.iterations,
        &challenge.server_public,
    )?;
    let mut random = [0u8; 16];
    rand::rng().fill_bytes(&mut random);
    tcp.write_all(&auth::packet2_wire(
        &secret.a_public,
        &secret.m1,
        &challenge.options,
        &random,
    ))
    .await?;

    // The server proof is length-prefixed. Pass/fail is the u32 after it.
    let proof_buf = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_counted(&mut tcp))
        .await
        .map_err(|_| SessionError::new("the Mac stopped answering during the sign-in"))??;
    // The server proves it knows the password, and the proof is checked.
    //
    // Our M1 was accepted by the server, and M1 is built from the session
    // key, so our key is the server's key and the proof we expect is the
    // server's proof. A server that cannot produce it does not know the
    // password, and a session with it would be a session whose every
    // secret the other end could read.
    let proofs = auth::server_proofs(&proof_buf[4..]);
    if proofs.is_empty() {
        tracing::warn!("the server's proof could not be read, so it was not checked");
    } else if proofs.iter().any(|proof| secret.m2_matches(proof)) {
        tracing::info!("the server proved that it knows the password");
    } else {
        // A server that cannot produce the proof does not know the
        // password, and every secret of this session would be readable by
        // it.
        //
        // This is reported rather than fatal: the exact shape of the
        // proof has not been confirmed against a live Mac, and a sign-in
        // that fails on a surprise is worse than a sign-in that warns.
        // Make it fatal once a live session has confirmed the framing.
        tracing::warn!("the server's proof did not match: this does not look like the Mac you expected");
        emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(
            "The Mac's identity proof did not match. Check that you are connected to the machine you meant.".into(),
        ))).await.ok();
    }
    let result = read_handshake(&mut tcp, 4).await?;
    if result != [0, 0, 0, 0] {
        return Err(SessionError::new("the server rejected the password"));
    }

    tcp.write_all(&[0xc1]).await?;
    let (server_w, server_h) = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_server_init(&mut tcp))
        .await
        .map_err(|_| SessionError::new("the Mac stopped answering during the sign-in"))??;
    emit(
        events,
        SessionEvent::DesktopResize {
            width: server_w,
            height: server_h,
        },
    )
    .await
    .ok();
    emit_state(events, SessionState::Negotiating).await.ok();

    tcp.write_all(&viewer_info()).await?;
    // Cleartext follow-up the server requires before it will emit the rekey.
    tcp.write_all(&[0x12, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])
        .await?;
    // Encodings go out in the clear. Without them the Mac never sends the
    // rekey, and the session sits on "negotiating" forever.
    tcp.write_all(&set_encodings()).await?;

    let wrap = secret.wrap_key;
    // The rekey can arrive as soon as SetEncryption(1) is sent, still in
    // the clear, as a framebuffer rectangle with encoding 0x44f.
    let layer = loop {
        let msg = read_clear_message(&mut tcp).await?;
        if let Some((key, iv)) = find_rekey(&msg, &wrap) {
            break RecordLayer::new(key, iv);
        }
    };

    let mut session = Live {
        tcp,
        layer,
        width: server_w,
        height: server_h,
        logical_width: server_w,
        logical_height: server_h,
        srtp: None,
        feedback: None,
        feedback_ssrc: 0,
        udp: None,
        ctrl: None,
        incoming: Vec::with_capacity(8192),
    };
    // This final toggle is CLEAR TEXT: it activates encryption for client
    // messages. Encrypting the toggle leaves the Mac waiting for it forever.
    session.tcp
        .write_all(&[0x12, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00])
        .await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    session.send_body(&set_encodings()).await?;
    let (offer, srtp_blob, feedback_blob) = crate::offer::media_offer();
    session.srtp = SrtpContext::from_blob(&srtp_blob);
    // The other half of the video key encrypts the feedback we send back.
    session.feedback = SrtcpEncryptor::from_blob(&feedback_blob);
    // Our own SSRC as the sender of that feedback. The Mac answers the
    // feedback it receives, and answers it to this address.
    let mut ssrc_bytes = [0u8; 4];
    rand::rng().fill_bytes(&mut ssrc_bytes);
    session.feedback_ssrc = u32::from_be_bytes(ssrc_bytes);
    // The sockets are bound before the offer goes out, so the media can
    // arrive the moment the Mac accepts it.
    session.bind_video(host, ports).await?;
    session.send_body(&offer).await?;
    session.send_body(&framebuffer_request(session.width, session.height)).await?;

    emit(
        events,
        SessionEvent::DesktopResize {
            width: session.width,
            height: session.height,
        },
    )
    .await
    .ok();
    emit_state(events, SessionState::Connected).await.ok();

    let udp = session.udp.take();
    let ctrl = session.ctrl.take();
    let mut srtp = session.srtp.take();
    let width = session.width;
    let height = session.height;
    let events2 = events.clone();
    // The video receiver has its own lifetime: it ends with the control
    // loop, not with the session. The session's token belongs to the
    // session, and a session that is being retried is not over.
    let cancel2 = cancel.child_token();
    let video_dest = format!("{host}:5901");
    let ctrl_dest = format!("{host}:5900");
    let media_dimensions = std::sync::Arc::new(std::sync::atomic::AtomicU32::new((u32::from(width) << 16) | u32::from(height)));
    let video_dimensions = media_dimensions.clone();
    // The physical-display controls talk to the Mac over SSH, and the
    // helper it runs takes seconds. That work does not belong in the loop
    // that carries the pointer and the keyboard, so it has a worker of its
    // own and the loop only waits for the answer.
    let (display_tx, mut display_rx) =
        mpsc::channel::<(remote_core::MacDisplayAction, mpsc::Sender<Result<remote_core::MacDisplayInfo, String>>)>(4);
    let display_host = host.to_string();
    let display_user = username.to_string();
    let display_password = password.to_string();
    let display_keys = host_keys.clone();
    let display_task = tokio::spawn(async move {
        let mut display: Option<crate::macos::DisplayController> = None;
        while let Some((action, reply)) = display_rx.recv().await {
            let result = async {
                if display.is_none() {
                    let verifier = display_keys
                        .clone()
                        .ok_or_else(|| "Mac display controls require the application's SSH host-key store".to_owned())?;
                    display = Some(
                        crate::macos::DisplayController::connect(
                            &display_host,
                            &display_user,
                            &display_password,
                            verifier,
                        )
                        .await?,
                    );
                }
                display.as_mut().expect("connected above").request(action).await
            }
            .await;
            if reply.send(result).await.is_err() {
                // The session went away while the Mac was working. The
                // result is dropped, and the restore below still happens.
                break;
            }
        }
        // The session is over. If this connection changed the physical
        // display, put it back: the person in front of the Mac should not
        // find their panel in a state they did not ask for.
        if let Some(mut display) = display {
            display.restore_on_disconnect().await;
        }
    });
    let mut display_reply: Option<mpsc::Receiver<Result<remote_core::MacDisplayInfo, String>>> = None;
    // The action the pending reply answers, so the answer is read for what
    // it is: reading the mode list says nothing about the desktop, and only
    // a change resizes the picture.
    let mut display_action: Option<remote_core::MacDisplayAction> = None;
    // The Mac's own geometry, learned from the first layout it sends.
    //
    // The options carry a canvas the caller asked for, which is not the
    // same thing: the Mac has a panel of a size of its own, and that is
    // what "native" means, what the quality presets are measured against,
    // and what a restore has to put back.
    let mut baseline: Option<(u16, u16)> = None;
    // Whether a resize has been asked for. The first layout after that is
    // the answer to the resize, not the Mac's own geometry.
    let mut resize_requested = false;
    // A preset chosen before the Mac's geometry is known.
    let mut pending_preset: Option<remote_core::QualityPreset> = None;
    // One resize round at a time (§10.9): 0x1d → 0x451 → re-offer → a picture
    // at the new size. A round is not over when the server answers it: the
    // encoder restarts after the answer, and a second request sent into
    // that restart races it (observed live as a black screen).
    let mut round = ResizeRound::default();
    // What the user is holding down, so it can be let go of. A session that
    // ends, loses focus, or is taken over must not leave a key or a mouse
    // button held on the remote machine.
    let mut held: Held = Held::default();
    // A view-only session sends no input at all.
    let mut view_only = false;
    // Ask for a fresh frame every tick, for servers whose damage tracking
    // cannot be trusted.
    let mut always_refresh = false;
    // The media generation. Every re-offer starts a new one, and a picture
    // carries the generation it belongs to, so "the new picture has arrived"
    // is a fact rather than a guess.
    let generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
    let picture_generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let video_generation = generation.clone();
    let video_picture_generation = picture_generation.clone();
    // A periodic tick, so a round can be finished, timed out or reported
    // without waiting for the next thing to happen on the wire.
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    // What the Mac's media path is doing, as its answer says.
    let mut media_state = remote_core::apple_media::MediaState::default();
    // The counters the video receiver keeps.
    let counters = std::sync::Arc::new(MediaCounters::default());
    let video_counters = counters.clone();
    // How many times the offer has been asked again because the answer was
    // empty.
    let mut offer_attempts = 0u32;
    // The feedback state travels with the video task: the requests are
    // about the video, and the video task is what notices that a picture
    // was lost.
    let mut feedback = session.feedback.take();
    let feedback_ssrc = session.feedback_ssrc;
    // The pictures go through a queue, so that a shell that is slow to take
    // them cannot stop the receiver reading the socket. A socket that is
    // not read overflows, and an overflow loses packets.
    let (picture_tx, mut picture_rx) = mpsc::channel::<crate::h264::AccessUnit>(PICTURE_QUEUE);
    let picture_events = events.clone();
    let picture_dimensions = video_dimensions.clone();
    let picture_task = tokio::spawn(async move {
        let mut pictures = 0u32;
        while let Some(unit) = picture_rx.recv().await {
            if !publish(&picture_events, vec![unit], &picture_dimensions, &mut pictures).await {
                break;
            }
        }
    });
    let peer = Peer::resolve(host, ports.0).await;
    let video_task = tokio::spawn(async move {
        if let (Some(sock), Some(ctx)) = (udp, srtp.as_mut()) {
            let mut buf = vec![0u8; 65535];
            let mut cbuf = vec![0u8; 2048];
            let mut punch = tokio::time::interval(Duration::from_millis(200));
            // A hole in the sequence numbers has to be given up on after a
            // short wait, or one lost packet would hold the stream still
            // for ever.
            let mut flush_tick = tokio::time::interval(Duration::from_millis(20));
            let mut packets = 0u32;
            let mut opened = 0u32;
            let mut pictures = 0u32;
            let mut active_ssrc: Option<u32> = None;
            let mut last_published = Instant::now();
            let mut stream_count = 1u32;
            let mut tiled_reported = false;
            let mut streams: std::collections::HashMap<u32, Stream> = std::collections::HashMap::new();
            // How many holes we have already asked about.
            let mut gaps_seen = 0u64;
            // The last time a keyframe was asked for, so a burst of loss
            // does not turn into a burst of requests.
            let mut last_request = Instant::now() - Duration::from_secs(10);
            // The media generation the video task last saw.
            let mut last_generation = 0u64;
            // Pictures the shell did not take in time.
            let mut dropped = 0u64;
            // Packets from somewhere other than the Mac.
            let mut stray = 0u64;
            loop {
                let n = tokio::select! {
                    _ = cancel2.cancelled() => break,
                    _ = punch.tick() => {
                        sock.send_to(&[0], &video_dest).await.ok();
                        if let Some(ctrl) = &ctrl {
                            ctrl.send_to(&[0], &ctrl_dest).await.ok();
                        }
                        continue;
                    }
                    _ = flush_tick.tick() => {
                        // Give up on a hole that has not been filled.
                        let Some(ssrc) = active_ssrc else { continue };
                        let Some(stream) = streams.get_mut(&ssrc) else { continue };
                        let units = stream.depay.flush();
                        if units.is_empty() { continue; }
                        if !publish(&events2, units, &video_dimensions, &mut pictures).await {
                            break;
                        }
                        continue;
                    }
                    r = sock.recv_from(&mut buf) => match r {
                        Ok((n, from)) => {
                            // Only the Mac's own packets are read. A stray
                            // datagram on the port is not part of the
                            // session, and treating one as video would put
                            // rubbish into the decoder.
                            if !peer.matches(&from) {
                                stray += 1;
                                if stray <= 3 || stray % 100 == 0 {
                                    tracing::warn!(%from, stray, "a packet from somewhere else was ignored");
                                }
                                continue;
                            }
                            n
                        }
                        Err(_) => break,
                    },
                    r = async {
                        match &ctrl {
                            Some(ctrl) => ctrl.recv(&mut cbuf).await,
                            None => std::future::pending().await,
                        }
                    } => {
                        let _ = r;
                        continue;
                    }
                };
                packets += 1;
                if packets <= 3 {
                    tracing::debug!(bytes = n, "Apple video datagram");
                }
                if n < 12 || buf[1] & 0x7f != 123 { continue; }
                let ssrc = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                // One stream per SSRC. The sequence space and the rollover
                // counter belong to the SSRC, and so does the assembly: two
                // streams interleaved into one assembler corrupt each other.
                if !streams.contains_key(&ssrc) && streams.len() >= MAX_STREAMS {
                    // The map is full of streams that are gone. Make room
                    // rather than refusing a stream that is real.
                    streams.clear();
                }
                let stream = streams.entry(ssrc).or_insert_with(|| Stream::new(&ctx));
                // Authenticate FIRST. A packet that does not authenticate
                // must not be able to change which stream is being shown, or
                // to take a slot in the map.
                let Some(rtp) = stream.srtp.unprotect(&buf[..n]) else {
                    if packets <= 3 {
                        tracing::debug!("SRTP authentication rejected");
                    }
                    continue;
                };
                opened += 1;
                if opened == 1 {
                    tracing::info!(payload_type = rtp.payload_type, "Apple SRTP video authenticated");
                }
                // Which stream is the one being shown?
                //
                // A new SSRC is a new encoder: a resized canvas or a
                // different quality tier. It is adopted when the stream we
                // are showing has gone quiet, and not before: switching
                // while the current stream is still publishing would show a
                // different picture every few hundred milliseconds.
                if active_ssrc != Some(ssrc) {
                    let quiet = last_published.elapsed() > STREAM_STALL;
                    if active_ssrc.is_none() || (quiet && stream_count == 1) {
                        tracing::info!(ssrc, previous = ?active_ssrc, "Apple video stream adopted");
                        active_ssrc = Some(ssrc);
                        stream.depay.reset();
                    } else {
                        // Another stream is publishing. Count it, report it,
                        // and keep showing the one that is working. Apple's
                        // tiled streams carry cross-references, so showing
                        // one tile on its own is not an option, and mixing
                        // them is worse than showing the wrong one.
                        if !tiled_reported {
                            tiled_reported = true;
                            tracing::warn!(
                                ssrc,
                                "the server is sending more than one video stream; only one is shown"
                            );
                        }
                        stream_count = stream_count.max(streams.len() as u32);
                        continue;
                    }
                }
                last_published = Instant::now();
                // A new media generation means the encoder restarted: the
                // first picture of the new stream is the one that says the
                // new size is good, and asking for it is what recovers a
                // restart whose first picture was lost.
                let generation = video_generation.load(std::sync::atomic::Ordering::SeqCst);
                if generation != last_generation {
                    last_generation = generation;
                    request_keyframe(&mut feedback, feedback_ssrc, ssrc, ctrl.as_ref(), &ctrl_dest, &mut last_request).await;
                }
                let units = stream.depay.push(rtp.seq, rtp.timestamp, rtp.marker, &rtp.payload);
                if !units.is_empty() {
                    // A picture belongs to the media generation that was
                    // running when it was decoded.
                    video_picture_generation.store(video_generation.load(std::sync::atomic::Ordering::SeqCst), std::sync::atomic::Ordering::SeqCst);
                    pictures += units.len() as u32;
                    video_counters
                        .pictures
                        .fetch_add(units.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    for unit in units {
                        // The queue never blocks the receiver. A picture that
                        // does not fit is dropped, and the decoder is given a
                        // fresh independent picture to recover with.
                        if picture_tx.try_send(unit).is_err() {
                            dropped += 1;
                            video_counters.recoveries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            request_keyframe(&mut feedback, feedback_ssrc, ssrc, ctrl.as_ref(), &ctrl_dest, &mut last_request).await;
                        }
                    }
                }
                // A lost packet leaves the decoder holding a picture that
                // refers to something it never received, and the picture
                // stays wrong until the next independent picture. Ask for
                // one.
                if stream.depay.stats.gaps > gaps_seen {
                    gaps_seen = stream.depay.stats.gaps;
                    video_counters.lost.store(stream.depay.stats.lost_packets, std::sync::atomic::Ordering::Relaxed);
                    video_counters.recoveries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // Ask for the packets that went missing, and for a
                    // fresh picture: the missing ones may come back, and
                    // the fresh one is what repairs the reference chain
                    // when they do not.
                    let missing = stream.depay.stats.lost_sequences.clone();
                    request_retransmission(&mut feedback, feedback_ssrc, ssrc, &missing, ctrl.as_ref(), &ctrl_dest).await;
                    request_keyframe(&mut feedback, feedback_ssrc, ssrc, ctrl.as_ref(), &ctrl_dest, &mut last_request).await;
                }
                // Report on the stream's health, so a picture that is going
                // wrong is visible in the log instead of being guessed at.
                if packets % 120 == 0 {
                    let stats = &stream.depay.stats;
                    if stats.gaps > 0 || stats.malformed > 0 || dropped > 0 {
                        tracing::info!(
                            gaps = stats.gaps,
                            lost = stats.lost_packets,
                            reordered = stats.reordered,
                            late = stats.late,
                            malformed = stats.malformed,
                            discarded = stats.discarded,
                            dropped,
                            "Apple video stream health"
                        );
                    }
                }
            }
            tracing::debug!(packets, opened, "Apple video receiver stopped");
        }
    });

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            cmd = commands.recv() => {
                match cmd {
                    None | Some(ClientCommand::Disconnect) => break,
                    Some(ClientCommand::Pointer { x, y, button_mask }) => {
                        if view_only {
                            // A view-only session must not move the remote
                            // pointer, not even to "release" it.
                            continue;
                        }
                        let body = crate::input::pointer(session.layer.wrap_key(), x, y, button_mask);
                        session.send_body(&body).await?;
                        held.pointer = Some((x, y, button_mask));
                    }
                    Some(ClientCommand::Key { keysym, down, .. }) => {
                        if view_only {
                            continue;
                        }
                        let mut body = [0u8; 8];
                        body[0] = 4;
                        body[1] = u8::from(down);
                        body[4..8].copy_from_slice(&keysym.to_be_bytes());
                        session.send_body(&body).await?;
                        if down {
                            held.keys.insert(keysym);
                        } else {
                            held.keys.remove(&keysym);
                        }
                    }
                    Some(ClientCommand::ReconnectNow) => {
                        // End the session so a new one can start. The
                        // supervisor notices the flag and starts it at
                        // once.
                        reconnect.store(true, std::sync::atomic::Ordering::SeqCst);
                        break;
                    }
                    Some(ClientCommand::ReleaseAllKeys) => {
                        // Let go of everything that is held. This is what a
                        // focus loss, a takeover or a disconnect needs, and
                        // the remote machine has no other way to learn about
                        // it.
                        release_all(&mut session, &mut held).await?;
                    }
                    Some(ClientCommand::SetViewOnly(on)) => {
                        if on && !view_only {
                            // Anything held was pressed under the old mode,
                            // so it is let go of first.
                            release_all(&mut session, &mut held).await?;
                        }
                        view_only = on;
                        tracing::info!(enabled = on, "view-only toggled");
                    }
                    Some(ClientCommand::SetAlwaysRefresh(on)) => {
                        always_refresh = on;
                        tracing::info!(enabled = on, "always-refresh toggled");
                    }
                    Some(ClientCommand::SetPreferScancodes(_)) => {
                        // The Apple path always sends keysyms, so the remote
                        // machine's layout decides what a key types. There is
                        // no scancode mode to switch to, and nothing to
                        // release: the encoding does not change.
                    }
                    Some(ClientCommand::TrustCertificate { .. }) => {
                        // Certificate trust is a property of the security
                        // handshake. Apple Screen Sharing authenticates with
                        // RSA-SRP and has no certificate to trust.
                    }
                    Some(ClientCommand::Agent(intent)) => {
                        // Answered rather than ignored. An agent is blocked
                        // on a settlement; a shrug here is an agent that
                        // waits for ever.
                        emit(
                            events,
                            SessionEvent::AgentRefused(intent.refuse(
                                "Apple Screen Sharing has no native command channel: this intent cannot be served over it",
                            )),
                        )
                        .await.ok();
                    }
                    Some(ClientCommand::Refresh) => {
                        session.send_body(&framebuffer_request(session.width, session.height)).await?;
                    }
                    Some(ClientCommand::SetQuality(preset)) => {
                        // Apple Remote Desktop's lever: the preset picks the
                        // resolution the Mac renders and streams. `0x451`
                        // below confirms what the server actually chose.
                        let Some(base) = baseline else {
                            // The Mac has not said how big its screen is yet,
                            // and the presets are measured against that. The
                            // choice is remembered and applied when it does.
                            pending_preset = Some(preset);
                            tracing::info!("a quality preset was chosen before the Mac's geometry was known");
                            continue;
                        };
                        let target = crate::quality::resolution_for(preset, base);
                        let current = (session.width, session.height);
                        resize_requested = true;
                        let base = baseline.unwrap_or(current);
                        request_resize(&mut session, &mut round, target, current, base).await?;
                    }
                    Some(ClientCommand::MacDisplay(action)) => {
                        use remote_core::MacDisplayAction;
                        let changes_mode = !matches!(action, MacDisplayAction::List);
                        if changes_mode {
                            // A pending stream resize was made for the old
                            // desktop, so it no longer means what it meant.
                            // A round that is already running is left to
                            // finish.
                            round.requested = None;
                        }
                        // The work happens on the display worker, so the
                        // pointer and the keyboard keep flowing while the
                        // Mac is busy.
                        let (reply, wait) = mpsc::channel(1);
                        display_action = Some(action);
                        if display_tx.send((action, reply)).await.is_err() {
                            emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(
                                "The Mac display controls are not available in this session.".into(),
                            ))).await.ok();
                        } else {
                            display_reply = Some(wait);
                        }
                    }
                    Some(ClientCommand::RequestResize { width, height }) => {
                        // In-band dynamic resize (RFC §10.9): 0x1d now, and the
                        // 0x451 that answers it drives the media re-offer.
                        //
                        // The bound is the size a Mac can display, not the
                        // size of a 4K television: the native button asks
                        // for the panel's own geometry, which on this Mac is
                        // 3600x2338, and a bound of 2160 refused it.
                        if (640..=8192).contains(&width) && (480..=8192).contains(&height) {
                            let current = (session.width, session.height);
                            resize_requested = true;
                            let base = baseline.unwrap_or(current);
                            request_resize(&mut session, &mut round, (width, height), current, base).await?;
                        } else {
                            emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice("That size is outside the range the Mac can stream.".into()))).await.ok();
                        }
                    }
                    _ => {}
                }
            }
            display = async {
                match &mut display_reply {
                    Some(reply) => reply.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                use remote_core::ProtocolEvent;
                let result = display.expect("a display reply");
                display_reply = None;
                let action = display_action.take();
                // Reading the mode list changes nothing, so it must not
                // resize the picture. A change does, and so does a restore.
                let changes_mode = !matches!(action, Some(remote_core::MacDisplayAction::List));
                if let Ok(info) = &result {
                    // Reading the mode list says nothing about the desktop,
                    // so it must not resize the picture. Only a change does.
                    if changes_mode {
                        session.width = info.pixel_width;
                        session.height = info.pixel_height;
                        media_dimensions.store((u32::from(info.pixel_width) << 16) | u32::from(info.pixel_height), std::sync::atomic::Ordering::Relaxed);
                        emit(events, SessionEvent::DesktopResize { width: info.pixel_width, height: info.pixel_height }).await.ok();
                    }
                }
                if result.is_ok() && changes_mode {
                    // Keep the SRTP keys, but re-offer after a physical
                    // mode change so the HP encoder starts its new canvas.
                    session.send_body(&offer).await?;
                    generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    session.send_body(&framebuffer_request(session.width, session.height)).await?;
                }
                emit(events, SessionEvent::Protocol(ProtocolEvent::AppleDisplay(result))).await.ok();
            }
            body = session.read_body() => {
                let body = body?;
                tracing::debug!(bytes = body.len(), "Apple control message");
                // A rekey inside the record layer rotates the content key.
                if let Some((key, iv)) = find_rekey(&body, session.layer.wrap_key()) {
                    // The key and IV change; the session's sequence counters
                    // do not. Resetting them would make the next record fail
                    // its integrity check and end the session.
                    let send_seq = session.layer.send_sequence();
                    let recv_seq = session.layer.recv_sequence();
                    session.layer.rekey(key, iv);
                    tracing::info!(send_seq, recv_seq, "Apple control layer rekeyed");
                }
                // The Mac's answer to the media offer: what the encoder
                // settled on, and how many tile streams it is using.
                if body.first() == Some(&0) {
                    if let Some(answer) = crate::answer::parse(&body) {
                        media_state.canvas_width = answer.canvas_width;
                        media_state.canvas_height = answer.canvas_height;
                        media_state.tiles = answer.tiles;
                        tracing::info!(
                            canvas_width = answer.canvas_width,
                            canvas_height = answer.canvas_height,
                            tiles = answer.tiles,
                            "the Mac answered the media offer"
                        );
                        if !answer.is_usable() {
                            // The Mac answered with an empty canvas, which
                            // it does while its encoder is still warming up.
                            // The offer is asked again.
                            if offer_attempts < MAX_OFFER_ATTEMPTS {
                                offer_attempts += 1;
                                tracing::info!(attempt = offer_attempts, "the Mac's answer was empty; asking again");
                                session.send_body(&offer).await?;
                            } else {
                                tracing::warn!("the Mac's answer was empty after several attempts");
                            }
                        } else {
                            emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleMedia(media_state))).await.ok();
                        }
                    }
                }
                // AppleDisplayLayout (0x451): authoritative geometry (R-A15).
                if let Some(((lw, lh), (bw, bh))) = find_display_layout(&body) {
                    let changed = (bw, bh) != (session.width, session.height);
                    session.width = bw;
                    session.height = bh;
                    // The layout also says how big the desktop is in points.
                    // On a retina display that is half the pixel size, and
                    // it is what a quality change must leave alone.
                    if lw > 0 && lh > 0 {
                        session.logical_width = lw;
                        session.logical_height = lh;
                    }
                    // The first layout, before anything was asked of the
                    // Mac, is the Mac's own geometry.
                    if baseline.is_none() && !resize_requested {
                        baseline = Some((bw, bh));
                        tracing::info!(
                            width = bw, height = bh,
                            logical_width = session.logical_width, logical_height = session.logical_height,
                            "the Mac's own geometry"
                        );
                        // A preset chosen before this is applied now.
                        if let Some(preset) = pending_preset.take() {
                            let base = baseline.unwrap_or((bw, bh));
                            let target = crate::quality::resolution_for(preset, base);
                            let current = (session.width, session.height);
                            resize_requested = true;
                            let base = baseline.unwrap_or(current);
                        request_resize(&mut session, &mut round, target, current, base).await?;
                        }
                    }
                    media_dimensions.store((u32::from(bw) << 16) | u32::from(bh), std::sync::atomic::Ordering::Relaxed);
                    if changed {
                        emit(events, SessionEvent::DesktopResize { width: bw, height: bh }).await.ok();
                    }
                    // R-A16b: re-arm the sender on every layout, geometry or not.
                    session.send_body(&auto_framebuffer(bw, bh)).await?;
                    session.send_body(&framebuffer_request(bw, bh)).await?;
                    if round.in_flight {
                        // §10.9 step 3: the re-offer is what restarts the
                        // encoder at the new canvas. Keys are reused.
                        //
                        // The round is NOT over yet. The encoder restarts
                        // after this answer, and a request sent into that
                        // restart races it. The round ends when a picture at
                        // the new size has been decoded.
                        session.send_body(&offer).await?;
                        generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        round.confirmed = Some((bw, bh));
                        round.needs_picture = changed;
                        round.awaiting_layout = false;
                        tracing::info!(bw, bh, "Apple display layout applied; media re-offered");
                    }
                }
            }
            _ = tick.tick() => {
                // The media state is reported every few seconds: how many
                // pictures have been decoded, how many packets went missing,
                // and how many times the picture was asked for again.
                media_state.pictures = counters.pictures.load(std::sync::atomic::Ordering::Relaxed);
                media_state.lost = counters.lost.load(std::sync::atomic::Ordering::Relaxed);
                media_state.recoveries = counters.recoveries.load(std::sync::atomic::Ordering::Relaxed);
                if media_state.pictures % 120 < 1 {
                    emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleMedia(media_state))).await.ok();
                }
                // A video receiver that died leaves a session that reports
                // itself connected and shows nothing. The supervisor
                // restarts it.
                if video_task.is_finished() {
                    tracing::warn!("the video receiver stopped; the session will be restarted");
                    break;
                }
                if always_refresh {
                    // The escape hatch for a server that does not report
                    // what changed. It costs the whole desktop in bandwidth
                    // every second, so it is off unless it is asked for.
                    session.send_body(&framebuffer_request(session.width, session.height)).await?;
                }
                // Finish, report or time out a resize round.
                if round.in_flight {
                    let picture_arrived = picture_generation.load(std::sync::atomic::Ordering::SeqCst)
                        >= generation.load(std::sync::atomic::Ordering::SeqCst);
                    // The layout has to come first: a picture from the old
                    // encoder says nothing about the size that was asked for.
                    if !round.awaiting_layout && (!round.needs_picture || picture_arrived) {
                        match finish_round(&mut round) {
                            RoundEnd::Send((w, h)) => {
                                tracing::info!(w, h, "Apple queued resize sent");
                                let (lw, lh) = (session.logical_width, session.logical_height);
                                let (mw, mh) = baseline.unwrap_or((session.width, session.height));
                                session.send_body(&display_config(w, h, lw, lh, mw, mh)).await?;
                            }
                            RoundEnd::Done(clamped) => {
                                tracing::info!("Apple resize round complete");
                                // The server may choose a different size when
                                // the request is more than it can do. Say so
                                // rather than leaving the user to guess.
                                if let Some((sent, confirmed)) = clamped {
                                    emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(
                                        format!("The Mac streams at {}x{}, not the {}x{} that was asked for.", confirmed.0, confirmed.1, sent.0, sent.1),
                                    ))).await.ok();
                                }
                            }
                        }
                    } else if let Some(sent_at) = round.sent_at {
                        if sent_at.elapsed() > RESIZE_TIMEOUT {
                            // The Mac did not answer in time. Say so, and
                            // leave the session where it was rather than
                            // waiting for ever.
                            round.in_flight = false;
                            round.sent_at = None;
                            round.requested = None;
                            tracing::warn!("Apple resize round timed out");
                            emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(
                                "The Mac did not answer the resize request. The picture is unchanged.".into(),
                            ))).await.ok();
                        }
                    }
                }
            }
        }
    }
    // Let go of anything that is held before the session goes away. A key
    // that was never released stays down on the remote machine, and the
    // person in front of it has no way to know why.
    release_all(&mut session, &mut held).await.ok();
    // The display worker restores the physical panel if this connection
    // changed it. Dropping the channel tells it to finish; waiting for it
    // means the restore actually happens before the session is gone.
    drop(display_tx);
    let _ = tokio::time::timeout(Duration::from_secs(25), display_task).await;
    video_task.abort();
    picture_task.abort();
    let _ = fail(events, "disconnected").await;
    Ok(())
}

struct Live {
    tcp: TcpStream,
    layer: RecordLayer,
    /// The picture size in pixels. This is what the decoder works in.
    width: u16,
    height: u16,
    /// The size of the desktop in points. On a retina display this is half
    /// the pixel size, and it is the size the person arranged their
    /// windows at, so a quality change must not change it.
    logical_width: u16,
    logical_height: u16,
    srtp: Option<SrtpContext>,
    /// Encrypts the RTCP feedback we send back to the Mac.
    feedback: Option<SrtcpEncryptor>,
    /// Our own SSRC, as the sender of that feedback.
    feedback_ssrc: u32,
    udp: Option<UdpSocket>,
    ctrl: Option<UdpSocket>,
    incoming: Vec<u8>,
}

impl Live {
    async fn send_body(&mut self, body: &[u8]) -> Result<(), SessionError> {
        let packet = self.layer.seal(body);
        self.tcp
            .write_all(&packet)
            .await
            .map_err(|e| SessionError::new(e.to_string()))
    }

    async fn read_body(&mut self) -> Result<Vec<u8>, SessionError> {
        loop {
            if self.incoming.len() >= 2 {
                let len = u16::from_be_bytes([self.incoming[0], self.incoming[1]]) as usize;
                if len == 0 || len % 16 != 0 {
                    return Err(SessionError::new("invalid Apple record length"));
                }
                if self.incoming.len() >= len + 2 {
                    let body = self.layer.open(&self.incoming[2..len + 2])
                        .map_err(|e| SessionError::new(e.to_string()))?;
                    self.incoming.drain(..len + 2);
                    return Ok(body);
                }
            }
            // read_buf is cancellation-safe. Mouse/key commands may win the
            // outer select at any time; partially read ciphertext must survive.
            if self.tcp.read_buf(&mut self.incoming).await? == 0 {
                return Err(SessionError::new("Apple control connection closed"));
            }
        }
    }

    async fn bind_video(&mut self, host: &str, ports: (u16, u16)) -> Result<(), SessionError> {
        // The Mac sends video from its UDP 5901 to our UDP 5901, and the
        // control stream the same way on 5900. An ephemeral port never
        // receives the picture. One outbound byte opens the firewall hole.
        let (video_port, control_port) = ports;
        let video = bind_udp(video_port)?;
        let ctrl = bind_udp(control_port)?;
        // The sockets are bound before the offer goes out, so the media can
        // arrive the moment the Mac accepts it.
        if let Err(error) = video.send_to(&[0], format!("{host}:{video_port}")).await {
            tracing::warn!(%error, "the first hole punch to the Mac did not get through");
        }
        if let Err(error) = ctrl.send_to(&[0], format!("{host}:{control_port}")).await {
            tracing::warn!(%error, "the first control hole punch to the Mac did not get through");
        }
        self.udp = Some(video);
        self.ctrl = Some(ctrl);
        Ok(())
    }
}

/// How much the socket is asked to hold, in bytes.
///
/// A picture is a burst of packets, and the decoder may be a moment behind
/// the wire. A small buffer overflows in exactly that moment, and an
/// overflow loses packets, and a lost packet corrupts the picture that
/// follows it. This is a request, not a promise: the kernel may cap it.
const RECEIVE_BUFFER: usize = 4 * 1024 * 1024;

fn bind_udp(port: u16) -> Result<UdpSocket, SessionError> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", port)).map_err(|e| {
        SessionError::new(format!(
            "UDP port {port} is not available ({e}). Another Apple session is probably using it: the Mac sends its video to this exact port, so two sessions to one Mac cannot share it."
        ))
    })?;
    // Ask for a big receive buffer, and say what we actually got.
    let reference = socket2::SockRef::from(&sock);
    if let Err(error) = reference.set_recv_buffer_size(RECEIVE_BUFFER) {
        tracing::warn!(%error, "the receive buffer could not be enlarged");
    }
    match reference.recv_buffer_size() {
        Ok(size) if size < RECEIVE_BUFFER => {
            tracing::info!(size, wanted = RECEIVE_BUFFER, "the receive buffer is smaller than asked for");
        }
        Ok(size) => tracing::debug!(size, "receive buffer ready"),
        Err(error) => tracing::warn!(%error, "the receive buffer size could not be read"),
    }
    sock.set_nonblocking(true)
        .map_err(|e| SessionError::new(e.to_string()))?;
    UdpSocket::from_std(sock).map_err(|e| SessionError::new(e.to_string()))
}

fn viewer_info() -> Vec<u8> {
    // type, pad, size (bytes after the size field), version, app id,
    // app version 6.1.0, OS version 15.3.0, then the 32-byte capability mask.
    let mut mask = [0u8; 32];
    mask[0] = 0xb0;
    mask[2] = 0x0c;
    mask[3] = 0x03;
    mask[4] = 0x90;
    mask[10] = 0x40;
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x21, 0x00]);
    msg.extend_from_slice(&0x3eu16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    for n in [2u32, 6, 1, 0, 15, 3, 0] {
        msg.extend_from_slice(&n.to_be_bytes());
    }
    msg.extend_from_slice(&mask);
    msg
}

/// `0x1d` SetDisplayConfiguration carrying the FULL dynamic descriptor
/// (RFC §7.1/§7.3): `display_flags = 1`, `display_type = 4`, `rotations = 7`,
/// a five-entry mode table scaled to the request, and a flat 1× HiDPI ratio
/// so `width`/`height` are streamed as-is (~¼ the pixels of a Retina table).
/// A mid-session request is answered with `0x451` + a re-offered encoder.
/// A display configuration for the Mac.
///
/// `width` and `height` are the PIXEL size the picture should be encoded
/// at, and `logical_width` and `logical_height` are the size of the desktop
/// in points. The two are separate on a retina display: a 3600x2338 panel
/// is 1800x1169 points.
///
/// The mode table keeps the logical size and changes the pixel size. That
/// is what makes a quality change a quality change: the desktop stays the
/// size the person arranged it at, and only the number of pixels that
/// arrive changes. A table that scaled the logical size with the pixel
/// size would resize the desktop, and a window the person had arranged
/// would move.
fn display_config(
    width: u16,
    height: u16,
    logical_width: u16,
    logical_height: u16,
    max_width: u16,
    max_height: u16,
) -> Vec<u8> {
    const MODE_COUNT: usize = 5;
    let di_size = 0x9c + 28 * MODE_COUNT;
    // message_size counts from AFTER the size field (RFC §7.1): the front
    // matter past the 4-byte prefix is 8 bytes, then the descriptor.
    let message_size = 8 + di_size;
    let mut m = Vec::with_capacity(4 + message_size);
    m.extend_from_slice(&[0x1d, 0x00]);
    m.extend_from_slice(&(message_size as u16).to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // version
    m.extend_from_slice(&1u16.to_be_bytes()); // display_count
    m.extend_from_slice(&0u32.to_be_bytes()); // header flags
    // Display descriptor, offsets from its start (RFC §7.1).
    m.extend_from_slice(&(di_size as u16).to_be_bytes()); // display_info_size
    let mut region = [0u8; 120];
    region[..b"DeskVNC".len()].copy_from_slice(b"DeskVNC");
    m.extend_from_slice(&region); // display_info_region, NUL-terminated name
    m.extend_from_slice(&1u32.to_be_bytes()); // display_flags: DYNAMIC_RESOLUTION
    // display_type 4. The value is required for a dynamic descriptor, and
    // the native viewer sends the same descriptor for the physical console
    // display, so it is not a request for a private display. The server
    // also uses the field to choose between its display paths, and that is
    // what the name "virtual" in the protocol notes comes from: the
    // meaning of the field is not the same thing as what the session
    // shows.
    m.extend_from_slice(&4u32.to_be_bytes());
    m.extend_from_slice(&369.45f32.to_be_bytes()); // physical mm (native)
    m.extend_from_slice(&207.82f32.to_be_bytes());
    // The maximum bounds are the Mac's own panel, so the server knows what
    // the screen really is. They must cover the request as well, or the
    // server clamps it: the native panel here is 3600x2338, taller than the
    // 2160 the native templates assume.
    m.extend_from_slice(&u32::from(width).max(u32::from(max_width)).to_be_bytes()); // max_width
    m.extend_from_slice(&u32::from(height).max(u32::from(max_height)).to_be_bytes()); // max_height
    m.extend_from_slice(&0u16.to_be_bytes()); // current_mode_index
    m.extend_from_slice(&0u16.to_be_bytes()); // preferred_mode_index
    m.extend_from_slice(&7u32.to_be_bytes()); // rotations — native sends 7
    m.extend_from_slice(&(MODE_COUNT as u16).to_be_bytes());
    // The mode table: the same desktop, at a different pixel size. The
    // first entry is the mode that is asked for; the others are the same
    // desktop at the sizes the server may prefer.
    let logical = (u32::from(logical_width).max(1), u32::from(logical_height).max(1));
    let mut modes: Vec<(u32, u32)> = vec![(width as u32, height as u32)];
    // A few smaller steps, so the server has something to choose from if it
    // does not want the size that was asked for.
    for step in [3u32, 2, 1] {
        let w = u32::from(width) * step / 4;
        let h = u32::from(height) * step / 4;
        modes.push((w.max(2), h.max(2)));
    }
    modes.push((width as u32, height as u32));
    debug_assert_eq!(modes.len(), MODE_COUNT);
    for (mw, mh) in modes {
        m.extend_from_slice(&mw.to_be_bytes()); // pixel width
        m.extend_from_slice(&mh.to_be_bytes()); // pixel height
        m.extend_from_slice(&logical.0.to_be_bytes()); // scaled width (points)
        m.extend_from_slice(&logical.1.to_be_bytes()); // scaled height (points)
        m.extend_from_slice(&60f64.to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes()); // mode flags
    }
    m
}

fn set_encodings() -> Vec<u8> {
    // Signed encoding ids. 1103 (0x44f) is the rekey; the rest are the
    // high-performance cursor, layout and media pseudo-encodings.
    let enc: [i32; 13] = [
        1010, 1011, 1002, 6, 16, 1104, 1100, -223, 1101, 1105, 1107, 1109, 1110,
    ];
    let mut m = vec![0x02, 0x00];
    m.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    for e in enc {
        m.extend_from_slice(&e.to_be_bytes());
    }
    m
}

/// AutoFrameBufferUpdate (0x09): a 16-byte fixed record (RFC §8.11). Arms
/// the server’s framebuffer/cursor sender; re-sent on every `0x451` (R-A16b).
fn auto_framebuffer(width: u16, height: u16) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[0] = 0x09;
    m[3] = 0x01;
    m[4..8].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    m[12..14].copy_from_slice(&width.to_be_bytes());
    m[14..16].copy_from_slice(&height.to_be_bytes());
    m
}

/// One rectangle of a framebuffer update.
struct WireRect<'a> {
    encoding: i32,
    payload: &'a [u8],
}

/// The rectangles of a framebuffer update, as far as they can be walked.
///
/// A rectangle's payload has no length of its own: the encoding says how
/// long it is. The two encodings this session cares about both say so, and
/// anything else stops the walk, because guessing would mean guessing
/// where the next rectangle starts.
fn rectangles(body: &[u8]) -> Vec<WireRect<'_>> {
    let mut out = Vec::new();
    if body.first() != Some(&0) || body.len() < 4 {
        return out;
    }
    let count = u16::from_be_bytes([body[2], body[3]]) as usize;
    let mut p = 4;
    for _ in 0..count {
        if p + 12 > body.len() {
            break;
        }
        let Ok(raw) = <[u8; 4]>::try_from(&body[p + 8..p + 12]) else { break };
        let encoding = i32::from_be_bytes(raw);
        p += 12;
        let payload = match encoding {
            // The rekey carries a fixed 36 byte body.
            0x44f => match body.get(p..p + 36) {
                Some(slice) => slice,
                None => break,
            },
            // The layout carries its own length. A message that is
            // shorter than it says is still worth reading: the fields that
            // matter are at the front.
            0x451 => {
                let Some(header) = body.get(p..p + 2) else { break };
                let len = u16::from_be_bytes([header[0], header[1]]) as usize;
                let end = (p + len).min(body.len());
                &body[p..end]
            }
            _ => break,
        };
        out.push(WireRect { encoding, payload });
        p += match encoding {
            0x44f => 36,
            _ => u16::from_be_bytes([body[p], body[p + 1]]) as usize,
        };
    }
    out
}

/// Extract `(scaled, backing)` geometry from an `AppleDisplayLayout` (`0x451`)
/// rectangle inside a decrypted control record (RFC §8.4). The layout is
/// authoritative: the server may answer a resize with a smaller fallback.
///
/// The layout is looked for in every rectangle, not only the first: a
/// message that carries something else first is still a message that
/// carries the layout.
fn find_display_layout(body: &[u8]) -> Option<((u16, u16), (u16, u16))> {
    for rect in rectangles(body) {
        if rect.encoding != 0x451 {
            continue;
        }
        let payload = rect.payload;
        if payload.len() < 12 {
            continue;
        }
        let ver = u16::from_be_bytes([payload[2], payload[3]]);
        if ver == 0 {
            continue;
        }
        let sw = u16::from_be_bytes([payload[4], payload[5]]);
        let sh = u16::from_be_bytes([payload[6], payload[7]]);
        let bw = u16::from_be_bytes([payload[8], payload[9]]);
        let bh = u16::from_be_bytes([payload[10], payload[11]]);
        if bw == 0 || bh == 0 {
            continue;
        }
        return Some(((sw, sh), (bw, bh)));
    }
    None
}

fn framebuffer_request(width: u16, height: u16) -> Vec<u8> {
    let mut m = vec![0x03, 0];
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&width.to_be_bytes());
    m.extend_from_slice(&height.to_be_bytes());
    m
}

/// How long one step of the handshake may take.
///
/// The handshake is a short conversation. A Mac that has gone away, or a
/// network that has stopped carrying, would otherwise leave the session
/// waiting for ever, with the pane showing nothing and no way to tell
/// that it is stuck.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Read one step of the handshake, with a deadline.
async fn read_handshake(
    tcp: &mut TcpStream,
    n: usize,
) -> Result<Vec<u8>, SessionError> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, read_exact(tcp, n))
        .await
        .map_err(|_| SessionError::new("the Mac stopped answering during the sign-in"))?
}

async fn read_exact(tcp: &mut TcpStream, n: usize) -> Result<Vec<u8>, SessionError> {
    let mut buf = vec![0u8; n];
    tcp.read_exact(&mut buf)
        .await
        .map_err(|e| SessionError::new(e.to_string()))?;
    Ok(buf)
}

async fn read_counted(tcp: &mut TcpStream) -> Result<Vec<u8>, SessionError> {
    let lenb = read_exact(tcp, 4).await?;
    let n = u32::from_be_bytes(lenb.clone().try_into().unwrap()) as usize;
    if n > 1_048_576 {
        return Err(SessionError::new("a handshake record was implausibly large"));
    }
    let mut rest = read_exact(tcp, n).await?;
    let mut all = lenb;
    all.append(&mut rest);
    Ok(all)
}

async fn read_rsa_key(tcp: &mut TcpStream) -> Result<Vec<u8>, SessionError> {
    let head = read_exact(tcp, 4).await?;
    let n = u32::from_be_bytes(head.try_into().unwrap()) as usize;
    if n < 10 || n > 8192 {
        return Err(SessionError::new("the server's public key framing was rejected"));
    }
    let rest = read_exact(tcp, n).await?;
    // 2-byte prefix, then u32 big-endian DER length, then the key.
    if rest.len() < 6 {
        return Err(SessionError::new("the server's public key was truncated"));
    }
    let der_len = u32::from_be_bytes(rest[2..6].try_into().unwrap()) as usize;
    rest.get(6..6 + der_len)
        .map(|s| s.to_vec())
        .ok_or_else(|| SessionError::new("the server's public key was truncated"))
}

async fn read_server_init(tcp: &mut TcpStream) -> Result<(u16, u16), SessionError> {
    let head = read_exact(tcp, 2 + 2 + 16 + 4).await?;
    let w = u16::from_be_bytes([head[0], head[1]]);
    let h = u16::from_be_bytes([head[2], head[3]]);
    let name = u32::from_be_bytes(head[20..24].try_into().unwrap()) as usize;
    if name > 4096 {
        return Err(SessionError::new("the server name was implausibly long"));
    }
    let _ = read_exact(tcp, name).await?;
    Ok((w, h))
}

async fn read_clear_message(tcp: &mut TcpStream) -> Result<Vec<u8>, SessionError> {
    let kind = read_exact(tcp, 1).await?[0];
    if kind != 0 {
        // Not a framebuffer update. Read nothing more; the caller loops and
        // this byte is lost, which is only safe because the rekey is a
        // framebuffer update. Surface it so a surprise message fails closed.
        return Err(SessionError::new(format!("unexpected cleartext message {kind:#x}")));
    }
    let header = read_exact(tcp, 3).await?;
    let n = u16::from_be_bytes([header[1], header[2]]) as usize;
    let mut msg = vec![kind];
    msg.extend(header);
    for _ in 0..n {
        let rect = read_exact(tcp, 12).await?;
        let enc = i32::from_be_bytes(rect[8..12].try_into().unwrap());
        msg.extend(&rect);
        let payload = if enc == 0x44f {
            read_exact(tcp, 36).await?
        } else {
            return Err(SessionError::new(format!("unsupported cleartext encoding {enc:#x}")));
        };
        msg.extend(payload);
    }
    Ok(msg)
}

fn find_rekey(msg: &[u8], wrap: &[u8; 16]) -> Option<([u8; 16], [u8; 16])> {
    // Only a framebuffer rectangle whose encoding is 1103 (0x44f). Any other
    // message happens to be at least 36 bytes, and treating its tail as a
    // rekey resets the cipher and the next record fails its integrity check.
    for rect in rectangles(msg) {
        if rect.encoding != 0x44f {
            continue;
        }
        let body = rect.payload;
        if body.len() < 36 {
            continue;
        }
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        key.copy_from_slice(&body[4..20]);
        iv.copy_from_slice(&body[20..36]);
        return Some(record::unwrap_rekey(wrap, &key, &iv));
    }
    None
}

#[derive(Debug)]
pub struct SessionError {
    message: String,
}

impl SessionError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SessionError {}

impl From<auth::AuthError> for SessionError {
    fn from(value: auth::AuthError) -> Self {
        Self::new(value.to_string())
    }
}

impl From<std::io::Error> for SessionError {
    fn from(value: std::io::Error) -> Self {
        Self::new(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srtp::SrtpEncryptor;

    #[test]
    fn a_whole_media_stream_survives_the_trip_from_the_wire() {
        // A fake Mac: an encoder that sends a key picture, then deltas, all
        // through the real SRTP protection and the real assembler. The
        // pictures that come out have to be right, because everything
        // downstream believes them.
        let blob = [42u8; 46];
        let mut sender = SrtpEncryptor::from_blob(&blob).expect("the keys");
        let mut receiver = SrtpContext::from_blob(&blob).expect("the keys");
        let mut depay = Depacketizer::default();

        // A key picture: an IDR, split over three packets, with the
        // parameter sets in front of it.
        let mut wire: Vec<(u16, u32, bool, Vec<u8>)> = Vec::new();
        wire.push((1, 100, false, vec![0x67, 0x64, 0x00, 0x1f]));
        wire.push((2, 100, false, vec![0x68, 0xee]));
        wire.push((3, 100, false, vec![0x7c, 0x85, 0xaa, 0xbb]));
        wire.push((4, 100, true, vec![0x7c, 0x45, 0xcc]));
        // Then a delta picture.
        wire.push((5, 200, true, vec![0x41, 0x9a]));

        let mut pictures = Vec::new();
        for (seq, timestamp, marker, payload) in wire {
            // The second byte of an RTP header carries the marker bit and
            // the payload type.
            let mut packet = vec![0x80, 123 | if marker { 0x80 } else { 0 }];
            packet.extend_from_slice(&seq.to_be_bytes());
            packet.extend_from_slice(&timestamp.to_be_bytes());
            packet.extend_from_slice(&7u32.to_be_bytes());
            packet.extend_from_slice(&payload);
            let protected = sender.protect(&packet).expect("the packet was protected");
            let rtp = receiver.unprotect(&protected).expect("the packet authenticated");
            assert_eq!(rtp.marker, marker, "the marker did not survive the wire");
            for unit in depay.push(rtp.seq, rtp.timestamp, rtp.marker, &rtp.payload) {
                pictures.push(unit);
            }
        }
        assert_eq!(pictures.len(), 2, "the stream did not produce two pictures");
        // The first is an IDR: it can start a decoder and it resets the
        // references.
        assert!(pictures[0].keyframe);
        assert!(pictures[0].reset);
        // The second is a delta: neither.
        assert!(!pictures[1].keyframe);
        assert!(!pictures[1].reset);
        // And the key picture carries the parameter sets with it, because a
        // decoder that has just been built needs them.
        assert!(pictures[0].annex_b.windows(4).any(|w| w == [0x67, 0x64, 0x00, 0x1f]));
        assert!(pictures[0].annex_b.windows(2).any(|w| w == [0x68, 0xee]));
    }

    #[tokio::test]
    async fn a_packet_from_somewhere_else_is_not_read_as_video() {
        // The Mac's own packets are read. A stray datagram on the port is
        // not part of the session, and reading one as video would put
        // rubbish into the decoder.
        let peer = Peer {
            addresses: vec!["10.0.0.5".parse().unwrap()],
            port: 5901,
        };
        assert!(peer.matches(&"10.0.0.5:5901".parse().unwrap()));
        assert!(!peer.matches(&"10.0.0.6:5901".parse().unwrap()));
        // The port is reported rather than enforced: a firewall in between
        // may change it, and dropping the media over that would be worse.
        assert!(peer.matches(&"10.0.0.5:40000".parse().unwrap()));
        // With nothing to check against, everything is read.
        let unknown = Peer { addresses: Vec::new(), port: 5901 };
        assert!(unknown.matches(&"192.168.1.2:1234".parse().unwrap()));
    }

    #[tokio::test]
    async fn the_retry_wait_ends_when_the_session_is_told_to_stop() {
        let (tx, mut rx) = mpsc::channel(4);
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut credentials = ("user".to_string(), "pass".to_string());
        tx.send(ClientCommand::Disconnect).await.unwrap();
        assert!(wait_for_retry(&mut rx, &cancel, Duration::from_secs(5), &mut credentials).await);
    }

    #[tokio::test]
    async fn the_retry_wait_ends_at_once_when_a_reconnect_is_asked_for() {
        let (tx, mut rx) = mpsc::channel(4);
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut credentials = ("user".to_string(), "pass".to_string());
        tx.send(ClientCommand::ReconnectNow).await.unwrap();
        let start = Instant::now();
        assert!(!wait_for_retry(&mut rx, &cancel, Duration::from_secs(30), &mut credentials).await);
        assert!(start.elapsed() < Duration::from_secs(1), "the retry waited anyway");
    }

    #[tokio::test]
    async fn the_retry_wait_takes_a_new_password_for_the_next_attempt() {
        let (tx, mut rx) = mpsc::channel(4);
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut credentials = ("user".to_string(), "old".to_string());
        tx.send(ClientCommand::ProvideCredentials {
            username: Some("other".to_string()),
            password: "new".to_string(),
            save: false,
        })
        .await
        .unwrap();
        tx.send(ClientCommand::ReconnectNow).await.unwrap();
        assert!(!wait_for_retry(&mut rx, &cancel, Duration::from_secs(30), &mut credentials).await);
        assert_eq!(credentials, ("other".to_string(), "new".to_string()));
    }

    #[tokio::test]
    async fn a_lost_picture_is_asked_for_again() {
        // The recovery path: a request for a fresh picture goes out on the
        // control socket, protected with the feedback keys, and starts with
        // a receiver report so the peer accepts it.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = format!("{}", socket.local_addr().unwrap());
        let mut encryptor = SrtcpEncryptor::from_blob(&[3; 46]).unwrap();
        let mut last = Instant::now() - Duration::from_secs(10);
        request_keyframe(&mut Some(encryptor), 0x1111_2222, 0x3333_4444, Some(&socket), &dest, &mut last).await;
        let mut buf = [0u8; 2048];
        let (n, _) = socket.recv_from(&mut buf).await.unwrap();
        assert!(n > 24);
        // The compound packet starts with the receiver report, in the clear.
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 201);
        assert_eq!(&buf[4..8], &0x1111_2222u32.to_be_bytes());
        // Everything after the receiver report is encrypted, so the
        // request itself is not readable on the wire.
        assert_ne!(&buf[8..12], &[0x84, 206, 0, 4]);
        assert_ne!(&buf[20..24], &0x3333_4444u32.to_be_bytes());
    }

    #[tokio::test]
    async fn a_request_is_not_sent_twice_in_a_row() {
        // A burst of loss must not turn into a burst of requests.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = format!("{}", socket.local_addr().unwrap());
        let mut encryptor = SrtcpEncryptor::from_blob(&[3; 46]).unwrap();
        let mut last = Instant::now() - Duration::from_secs(10);
        request_keyframe(&mut Some(encryptor), 1, 2, Some(&socket), &dest, &mut last).await;
        let mut buf = [0u8; 2048];
        socket.recv_from(&mut buf).await.unwrap();
        // The second request is held back.
        let mut encryptor = SrtcpEncryptor::from_blob(&[3; 46]).unwrap();
        request_keyframe(&mut Some(encryptor), 1, 2, Some(&socket), &dest, &mut last).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buf)).await.is_err(),
            "a second request was sent straight after the first"
        );
    }

    #[tokio::test]
    async fn releasing_everything_held_says_so_on_the_wire() {
        // A key or a button that was pressed and never released stays down on
        // the remote machine. The only way to release it is to say so.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let mut live = Live {
            tcp,
            layer: RecordLayer::new([1; 16], [2; 16]),
            width: 1, height: 1, logical_width: 1, logical_height: 1,
            srtp: None, feedback: None, feedback_ssrc: 0,
            udp: None, ctrl: None,
            incoming: Vec::with_capacity(8192),
        };
        let mut held = Held::default();
        held.keys.insert(0x61);
        held.keys.insert(0x62);
        held.pointer = Some((10, 20, 1));
        release_all(&mut live, &mut held).await.unwrap();
        assert!(held.keys.is_empty());
        assert!(held.pointer.is_none());

        // The server sees a pointer event with no buttons and two key ups.
        let mut receiver = RecordLayer::new([1; 16], [2; 16]);
        let mut bodies = Vec::new();
        for _ in 0..3 {
            let mut header = [0u8; 2];
            server.read_exact(&mut header).await.unwrap();
            let len = u16::from_be_bytes(header) as usize;
            let mut packet = vec![0u8; len];
            server.read_exact(&mut packet).await.unwrap();
            bodies.push(receiver.open(&packet).unwrap());
        }
        assert_eq!(bodies[0][0], 0x10, "the pointer was not released");
        assert_eq!(bodies[1][0], 4, "a key was not released");
        assert_eq!(bodies[1][1], 0, "the key release was a key press");
        assert_eq!(bodies[2][0], 4);
        assert_eq!(bodies[2][1], 0);
    }

    #[tokio::test]
    async fn interrupted_record_read_keeps_partial_ciphertext() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let mut live = Live {
            tcp,
            layer: RecordLayer::new([1; 16], [2; 16]),
            width: 1, height: 1, logical_width: 1, logical_height: 1,
            srtp: None, feedback: None, feedback_ssrc: 0,
            udp: None, ctrl: None,
            incoming: Vec::with_capacity(8192),
        };
        let mut sender = RecordLayer::new([1; 16], [2; 16]);
        let packet = sender.seal(b"control reply");
        server.write_all(&packet[..5]).await.unwrap();
        // Simulate a click winning the outer select while a reply is partial.
        assert!(tokio::time::timeout(Duration::from_millis(20), live.read_body()).await.is_err());
        assert_eq!(live.incoming.len(), 5);
        server.write_all(&packet[5..]).await.unwrap();
        assert_eq!(live.read_body().await.unwrap(), b"control reply");
        assert!(live.incoming.is_empty());
    }

    #[test]
    fn display_metadata_does_not_reset_the_record_cipher() {
        let mut layout = vec![0; 94];
        layout[2..4].copy_from_slice(&1u16.to_be_bytes());
        layout[12..16].copy_from_slice(&1105i32.to_be_bytes());
        assert!(find_rekey(&layout, &[0; 16]).is_none());
    }

    #[test]
    fn dynamic_display_config_matches_the_native_shape() {
        let m = display_config(1920, 1080, 1800, 1169, 3600, 2338);
        assert_eq!(m[0], 0x1d);
        let message_size = u16::from_be_bytes([m[2], m[3]]) as usize;
        assert_eq!(message_size, m.len() - 4);
        assert_eq!(u16::from_be_bytes([m[4], m[5]]), 1); // version
        assert_eq!(u16::from_be_bytes([m[6], m[7]]), 1); // display_count
        let d = 12;
        let di_size = u16::from_be_bytes([m[d], m[d + 1]]) as usize;
        assert_eq!(di_size, 0x9c + 5 * 28);
        assert_eq!(u32::from_be_bytes(m[d + 0x7a..d + 0x7e].try_into().unwrap()), 1); // dynamic flag
        assert_eq!(u32::from_be_bytes(m[d + 0x7e..d + 0x82].try_into().unwrap()), 4); // display_type
        // The maximum bounds are the Mac's own panel.
        assert_eq!(u32::from_be_bytes(m[d + 0x8a..d + 0x8e].try_into().unwrap()), 3600);
        assert_eq!(u32::from_be_bytes(m[d + 0x8e..d + 0x92].try_into().unwrap()), 2338);
        assert_eq!(u16::from_be_bytes(m[d + 0x92..d + 0x94].try_into().unwrap()), 0); // mode index < count
        assert_eq!(u32::from_be_bytes(m[d + 0x96..d + 0x9a].try_into().unwrap()), 7);
        assert_eq!(u16::from_be_bytes(m[d + 0x9a..d + 0x9c].try_into().unwrap()), 5);
        let mode = d + 0x9c;
        assert_eq!(u32::from_be_bytes(m[mode..mode + 4].try_into().unwrap()), 1920);
        assert_eq!(u32::from_be_bytes(m[mode + 4..mode + 8].try_into().unwrap()), 1080);
        assert_eq!(f64::from_be_bytes(m[mode + 16..mode + 24].try_into().unwrap()), 60.0);
    }

    /// A framebuffer update carrying one rectangle with the given encoding
    /// and payload.
    fn update_with(encoding: i32, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8, 0, 0, 1];
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // x, y, w, h
        body.extend_from_slice(&encoding.to_be_bytes());
        body.extend_from_slice(payload);
        body
    }

    #[test]
    fn the_layout_is_found_after_another_rectangle() {
        // A message that carries something else first is still a message
        // that carries the layout.
        let mut body = vec![0u8, 0, 0, 2];
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(&1103i32.to_be_bytes()); // the rekey
        body.extend_from_slice(&[0u8; 36]);
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(&1105i32.to_be_bytes()); // the layout
        let mut payload = vec![0u8; 82];
        payload[0..2].copy_from_slice(&82u16.to_be_bytes());
        payload[2..4].copy_from_slice(&5u16.to_be_bytes());
        payload[4..6].copy_from_slice(&1800u16.to_be_bytes());
        payload[6..8].copy_from_slice(&1169u16.to_be_bytes());
        payload[8..10].copy_from_slice(&3600u16.to_be_bytes());
        payload[10..12].copy_from_slice(&2338u16.to_be_bytes());
        body.extend_from_slice(&payload);
        assert_eq!(find_display_layout(&body), Some(((1800, 1169), (3600, 2338))));
    }

    #[test]
    fn a_rekey_is_found_after_another_rectangle() {
        let mut body = vec![0u8, 0, 0, 2];
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(&1105i32.to_be_bytes()); // the layout
        let mut payload = vec![0u8; 82];
        payload[0..2].copy_from_slice(&82u16.to_be_bytes());
        body.extend_from_slice(&payload);
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(&1103i32.to_be_bytes()); // the rekey
        body.extend_from_slice(&[0u8; 36]);
        // The rekey is recognised by its encoding, wherever it is.
        assert!(find_rekey(&body, &[0; 16]).is_some());
    }

    #[test]
    fn a_rekey_is_not_mistaken_for_something_else() {
        // A message with a long body that is not a rekey must not be
        // treated as one: doing that resets the cipher and the next record
        // fails its integrity check.
        let body = update_with(1104, &[0u8; 64]);
        assert!(find_rekey(&body, &[0; 16]).is_none());
    }

    #[test]
    fn a_quality_change_keeps_the_desktop_the_size_it_was() {
        // The mode table says how big the desktop is in points and how many
        // pixels it is encoded at. A quality change must change the pixels
        // and leave the points alone: a window the person arranged would
        // otherwise move.
        let m = display_config(2216, 1440, 1800, 1169, 3600, 2338);
        let d = 12;
        let mode = d + 0x9c;
        for entry in 0..5 {
            let at = mode + entry * 28;
            let pixel_w = u32::from_be_bytes(m[at..at + 4].try_into().unwrap());
            let pixel_h = u32::from_be_bytes(m[at + 4..at + 8].try_into().unwrap());
            let scaled_w = u32::from_be_bytes(m[at + 8..at + 12].try_into().unwrap());
            let scaled_h = u32::from_be_bytes(m[at + 12..at + 16].try_into().unwrap());
            assert_eq!(scaled_w, 1800, "the desktop width moved");
            assert_eq!(scaled_h, 1169, "the desktop height moved");
            assert!(pixel_w > 0 && pixel_h > 0);
        }
        // And the first entry is the size that was asked for.
        assert_eq!(u32::from_be_bytes(m[mode..mode + 4].try_into().unwrap()), 2216);
        assert_eq!(u32::from_be_bytes(m[mode + 4..mode + 8].try_into().unwrap()), 1440);
    }

    #[test]
    fn display_layout_yields_backing_geometry() {
        let mut body = vec![0u8, 0, 0, 1];
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // x, y, w, h
        body.extend_from_slice(&1105i32.to_be_bytes());
        body.extend_from_slice(&0x52u16.to_be_bytes()); // payload_len
        body.extend_from_slice(&5u16.to_be_bytes()); // version
        body.extend_from_slice(&1800u16.to_be_bytes()); // scaled w
        body.extend_from_slice(&1169u16.to_be_bytes()); // scaled h
        body.extend_from_slice(&3600u16.to_be_bytes()); // backing w
        body.extend_from_slice(&2338u16.to_be_bytes()); // backing h
        assert_eq!(find_display_layout(&body), Some(((1800, 1169), (3600, 2338))));
        // 1105 BE is 00 00 04 51, so clobber the 0x04 byte to break the tag.
        body[12..16].copy_from_slice(&1104i32.to_be_bytes());
        assert_eq!(find_display_layout(&body), None);
    }

    #[test]
    fn viewer_info_size_matches_its_payload() {
        let msg = viewer_info();
        assert_eq!(msg[0], 0x21);
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]) as usize, msg.len() - 4);
    }

    #[test]
    fn a_resize_request_for_the_size_already_shown_does_nothing() {
        let mut round = ResizeRound::default();
        assert_eq!(plan_resize(&mut round, (1920, 1080), (1920, 1080)), ResizeAction::Nothing);
        assert!(!round.in_flight);
    }

    #[test]
    fn a_resize_request_starts_a_round() {
        let mut round = ResizeRound::default();
        assert_eq!(plan_resize(&mut round, (1663, 1080), (1920, 1080)), ResizeAction::Send((1663, 1080)));
        assert!(round.in_flight);
        assert_eq!(round.sent, Some((1663, 1080)));
    }

    #[test]
    fn a_request_during_a_round_is_remembered_and_sent_when_the_round_ends() {
        let mut round = ResizeRound::default();
        plan_resize(&mut round, (1663, 1080), (1920, 1080));
        // A second request arrives while the first is still running.
        assert_eq!(plan_resize(&mut round, (2560, 1440), (1920, 1080)), ResizeAction::Wait);
        // The round ends: the newer request goes out.
        assert_eq!(finish_round(&mut round), RoundEnd::Send((2560, 1440)));
        assert!(round.in_flight);
        assert_eq!(round.sent, Some((2560, 1440)));
    }

    #[test]
    fn a_request_for_the_size_before_the_round_is_not_lost() {
        // The user asks for Low, then for the size the session had before.
        // The second request asks for the CURRENT size, so a check against
        // the current size would drop it, and the session would end up at
        // the size the user asked for first.
        let mut round = ResizeRound::default();
        plan_resize(&mut round, (1663, 1080), (1920, 1080));
        assert_eq!(plan_resize(&mut round, (1920, 1080), (1920, 1080)), ResizeAction::Wait);
        assert_eq!(finish_round(&mut round), RoundEnd::Send((1920, 1080)));
    }

    #[test]
    fn a_round_ends_with_the_size_the_server_chose_when_it_differs() {
        let mut round = ResizeRound::default();
        plan_resize(&mut round, (3000, 2000), (1920, 1080));
        // The server answered with a different size.
        round.confirmed = Some((2560, 1440));
        assert_eq!(finish_round(&mut round), RoundEnd::Done(Some(((3000, 2000), (2560, 1440)))));
        assert!(!round.in_flight);
    }

    #[test]
    fn a_round_ends_quietly_when_the_server_chose_what_was_asked() {
        let mut round = ResizeRound::default();
        plan_resize(&mut round, (1663, 1080), (1920, 1080));
        round.confirmed = Some((1663, 1080));
        assert_eq!(finish_round(&mut round), RoundEnd::Done(None));
    }

    #[test]
    fn a_round_waits_for_the_layout_before_the_picture() {
        let mut round = ResizeRound::default();
        plan_resize(&mut round, (1663, 1080), (1920, 1080));
        // A picture from the old encoder must not end the round: the layout
        // that answers the request has not arrived yet.
        assert!(round.awaiting_layout);
        round.confirmed = Some((1663, 1080));
        round.needs_picture = true;
        round.awaiting_layout = false;
        assert!(round.in_flight);
    }

    #[test]
    fn a_round_waits_for_a_picture_at_the_new_size() {
        let mut round = ResizeRound::default();
        plan_resize(&mut round, (1663, 1080), (1920, 1080));
        // The layout arrived: the round is not over, the encoder restarts
        // and the new picture has to arrive.
        round.confirmed = Some((1663, 1080));
        round.needs_picture = true;
        assert!(round.in_flight);
        // Only a layout that did not change the geometry ends the round
        // straight away.
        round.needs_picture = false;
        assert_eq!(finish_round(&mut round), RoundEnd::Done(None));
    }
}

