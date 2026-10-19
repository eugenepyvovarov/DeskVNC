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
use crate::srtp::SrtpContext;

/// How many distinct video streams are remembered at once. A resized canvas
/// or a new quality tier brings a new SSRC; the old ones are dropped.
const MAX_STREAMS: usize = 32;

/// How long the shown stream may be silent before another stream is taken
/// to be the live one.
const STREAM_STALL: Duration = Duration::from_millis(750);

/// How long a resize round may take before the session gives up on it and
/// says so.
const RESIZE_TIMEOUT: Duration = Duration::from_secs(8);

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
) -> Result<(), SessionError> {
    match plan_resize(round, target, current) {
        ResizeAction::Nothing => Ok(()),
        ResizeAction::Wait => {
            tracing::debug!(w = target.0, h = target.1, "Apple resize request queued");
            Ok(())
        }
        ResizeAction::Send((w, h)) => {
            session.send_body(&display_config(w, h)).await?;
            tracing::info!(w, h, "Apple display resize requested");
            Ok(())
        }
    }
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
    let mut username = options.credentials.username.clone().unwrap_or_default();
    let mut password = options.credentials.password.clone().unwrap_or_default();
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
    let (width, height) = match &options.protocol {
        remote_core::ProtocolOptions::Apple(o) => (o.width, o.height),
        _ => (1920, 1080),
    };
    let result = connect(&options.host, options.port, &username, &password, width, height, &events, &mut commands, &cancel, host_keys).await;
    // Also stop the UDP task if the control loop exits through an error.
    cancel.cancel();
    if let Err(err) = result {
        let _ = fail(&events, &err.to_string()).await;
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
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &tokio_util::sync::CancellationToken,
    host_keys: Option<crate::macos::Verifier>,
) -> Result<(), SessionError> {
    emit_state(events, SessionState::Connecting).await.ok();
    let mut tcp = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect((host, port)))
        .await
        .map_err(|_| SessionError::new("timed out connecting"))?
        .map_err(|e| SessionError::new(e.to_string()))?;
    tcp.set_nodelay(true).ok();

    let banner = read_exact(&mut tcp, 12).await?;
    if &banner != b"RFB 003.889\n" {
        return Err(SessionError::new("the server did not offer Apple Screen Sharing"));
    }
    tcp.write_all(b"RFB 003.889\n").await?;
    let count = read_exact(&mut tcp, 1).await?[0] as usize;
    if count == 0 {
        return Err(SessionError::new("the server refused the connection"));
    }
    let types = read_exact(&mut tcp, count).await?;
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
    let der = read_rsa_key(&mut tcp).await?;
    let identity = auth::seal_identity(&der, username)?;
    tcp.write_all(&auth::rsa1_packet(2, 0x0100, &identity, 384)).await?;

    let challenge_buf = read_counted(&mut tcp).await?;
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
    let proof_buf = read_counted(&mut tcp).await?;
    let _ = proof_buf;
    let result = read_exact(&mut tcp, 4).await?;
    if result != [0, 0, 0, 0] {
        return Err(SessionError::new("the server rejected the password"));
    }

    tcp.write_all(&[0xc1]).await?;
    let (server_w, server_h) = read_server_init(&mut tcp).await?;
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
        video: Depacketizer::default(),
        srtp: None,
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
    let (offer, srtp_blob) = crate::offer::media_offer();
    session.srtp = SrtpContext::from_blob(&srtp_blob);
    session.send_body(&offer).await?;
    session.send_body(&framebuffer_request(session.width, session.height)).await?;
    session.bind_video(host).await?;

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
    let cancel2 = cancel.clone();
    let video_dest = format!("{host}:5901");
    let ctrl_dest = format!("{host}:5900");
    let media_dimensions = std::sync::Arc::new(std::sync::atomic::AtomicU32::new((u32::from(width) << 16) | u32::from(height)));
    let video_dimensions = media_dimensions.clone();
    let mut display: Option<crate::macos::DisplayController> = None;
    let native = (width, height);
    // One resize round at a time (§10.9): 0x1d → 0x451 → re-offer → a picture
    // at the new size. A round is not over when the server answers it: the
    // encoder restarts after the answer, and a second request sent into
    // that restart races it (observed live as a black screen).
    let mut round = ResizeRound::default();
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
                    r = sock.recv(&mut buf) => match r {
                        Ok(n) => n,
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
                let units = stream.depay.push(rtp.seq, rtp.timestamp, rtp.marker, &rtp.payload);
                if !units.is_empty() {
                    // A picture belongs to the media generation that was
                    // running when it was decoded.
                    video_picture_generation.store(video_generation.load(std::sync::atomic::Ordering::SeqCst), std::sync::atomic::Ordering::SeqCst);
                }
                if !publish(&events2, units, &video_dimensions, &mut pictures).await {
                    break;
                }
                // Report on the stream's health, so a picture that is going
                // wrong is visible in the log instead of being guessed at.
                if packets % 120 == 0 {
                    let stats = stream.depay.stats;
                    if stats.gaps > 0 || stats.malformed > 0 {
                        tracing::info!(
                            gaps = stats.gaps,
                            lost = stats.lost_packets,
                            reordered = stats.reordered,
                            late = stats.late,
                            malformed = stats.malformed,
                            discarded = stats.discarded,
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
                        let body = crate::input::pointer(session.layer.wrap_key(), x, y, button_mask);
                        session.send_body(&body).await?;
                    }
                    Some(ClientCommand::Key { keysym, down, .. }) => {
                        let mut body = [0u8; 8];
                        body[0] = 4;
                        body[1] = u8::from(down);
                        body[4..8].copy_from_slice(&keysym.to_be_bytes());
                        session.send_body(&body).await?;
                    }
                    Some(ClientCommand::Refresh) => {
                        session.send_body(&framebuffer_request(session.width, session.height)).await?;
                    }
                    Some(ClientCommand::SetQuality(preset)) => {
                        // Apple Remote Desktop's lever: the preset picks the
                        // resolution the Mac renders and streams. `0x451`
                        // below confirms what the server actually chose.
                        let target = crate::quality::resolution_for(preset, native);
                        let current = (session.width, session.height);
                        request_resize(&mut session, &mut round, target, current).await?;
                    }
                    Some(ClientCommand::MacDisplay(action)) => {
                        use remote_core::{MacDisplayAction, ProtocolEvent};
                        let changes_mode = !matches!(action, MacDisplayAction::List);
                        let result = async {
                            if display.is_none() {
                                let verifier = host_keys.clone().ok_or_else(|| "Mac display controls require the application's SSH host-key store".to_owned())?;
                                display = Some(crate::macos::DisplayController::connect(host, username, password, verifier).await?);
                            }
                            if changes_mode {
                                // A pending stream resize was made for the
                                // old desktop, so it no longer means what it
                                // meant. A round that is already running is
                                // left to finish.
                                round.requested = None;
                            }
                            display.as_mut().unwrap().request(action).await
                        }.await;
                        if let Ok(info) = &result {
                            session.width = info.pixel_width;
                            session.height = info.pixel_height;
                            media_dimensions.store((u32::from(info.pixel_width) << 16) | u32::from(info.pixel_height), std::sync::atomic::Ordering::Relaxed);
                            emit(events, SessionEvent::DesktopResize { width: info.pixel_width, height: info.pixel_height }).await.ok();
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
                            request_resize(&mut session, &mut round, (width, height), current).await?;
                        } else {
                            emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice("That size is outside the range the Mac can stream.".into()))).await.ok();
                        }
                    }
                    _ => {}
                }
            }
            body = session.read_body() => {
                let body = body?;
                tracing::debug!(bytes = body.len(), "Apple control message");
                // A rekey inside the record layer rotates the content key.
                if let Some((key, iv)) = find_rekey(&body, session.layer.wrap_key()) {
                    session.layer = RecordLayer::new(key, iv);
                }
                // AppleDisplayLayout (0x451): authoritative geometry (R-A15).
                if let Some((_, (bw, bh))) = find_display_layout(&body) {
                    let changed = (bw, bh) != (session.width, session.height);
                    session.width = bw;
                    session.height = bh;
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
                                session.send_body(&display_config(w, h)).await?;
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
    video_task.abort();
    let _ = fail(events, "disconnected").await;
    Ok(())
}

struct Live {
    tcp: TcpStream,
    layer: RecordLayer,
    width: u16,
    height: u16,
    video: Depacketizer,
    srtp: Option<SrtpContext>,
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

    async fn bind_video(&mut self, host: &str) -> Result<(), SessionError> {
        // The Mac sends video from its UDP 5901 to our UDP 5901, and the
        // control stream the same way on 5900. An ephemeral port never
        // receives the picture. One outbound byte opens the firewall hole.
        let video = bind_udp(5901)?;
        let ctrl = bind_udp(5900)?;
        video.send_to(&[0], format!("{host}:5901")).await.ok();
        ctrl.send_to(&[0], format!("{host}:5900")).await.ok();
        self.udp = Some(video);
        self.ctrl = Some(ctrl);
        Ok(())
    }
}

fn bind_udp(port: u16) -> Result<UdpSocket, SessionError> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", port)).map_err(|e| {
        SessionError::new(format!("UDP {port} is already in use ({e})"))
    })?;
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
fn display_config(width: u16, height: u16) -> Vec<u8> {
    const MODE_COUNT: usize = 5;
    const NATIVE_MODES: [(u32, u32, u32, u32); MODE_COUNT] = [
        (3840, 2160, 1920, 1080),
        (2880, 1800, 1440, 900),
        (3840, 2160, 1920, 1080),
        (2880, 1620, 1440, 810),
        (2624, 1696, 1312, 848),
    ];
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
    m.extend_from_slice(&4u32.to_be_bytes()); // display_type: virtual
    m.extend_from_slice(&369.45f32.to_be_bytes()); // physical mm (native)
    m.extend_from_slice(&207.82f32.to_be_bytes());
    // max bounds MUST cover the request (native here is 3600×2338, taller
    // than the 2160 the native templates assume) or the server clamps.
    m.extend_from_slice(&u32::from(width).max(3840).to_be_bytes()); // max_width
    m.extend_from_slice(&u32::from(height).max(2160).to_be_bytes()); // max_height
    m.extend_from_slice(&0u16.to_be_bytes()); // current_mode_index
    m.extend_from_slice(&0u16.to_be_bytes()); // preferred_mode_index
    m.extend_from_slice(&7u32.to_be_bytes()); // rotations — native sends 7
    m.extend_from_slice(&(MODE_COUNT as u16).to_be_bytes());
    let sx = f64::from(width) / 1920.0;
    let sy = f64::from(height) / 1080.0;
    for (_, _, sw, sh) in NATIVE_MODES {
        let msw = (f64::from(sw) * sx + 0.5) as u32;
        let msh = (f64::from(sh) * sy + 0.5) as u32;
        m.extend_from_slice(&msw.to_be_bytes()); // pixel width (flat 1×)
        m.extend_from_slice(&msh.to_be_bytes());
        m.extend_from_slice(&msw.to_be_bytes()); // scaled width
        m.extend_from_slice(&msh.to_be_bytes());
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

/// Extract `(scaled, backing)` geometry from an `AppleDisplayLayout` (`0x451`)
/// rectangle inside a decrypted control record (RFC §8.4). The layout is
/// authoritative: the server may answer a resize with a smaller fallback.
fn find_display_layout(body: &[u8]) -> Option<((u16, u16), (u16, u16))> {
    if body.first() != Some(&0) || body.len() < 16 { return None; }
    let rects = u16::from_be_bytes([body[2], body[3]]) as usize;
    let mut p = 4;
    for _ in 0..rects {
        if p + 12 > body.len() { return None; }
        let enc = i32::from_be_bytes(body[p + 8..p + 12].try_into().ok()?);
        p += 12;
        if enc != 0x451 { return None; }
        if p + 12 > body.len() { return None; }
        let ver = u16::from_be_bytes([body[p + 2], body[p + 3]]);
        if ver == 0 { return None; }
        let sw = u16::from_be_bytes([body[p + 4], body[p + 5]]);
        let sh = u16::from_be_bytes([body[p + 6], body[p + 7]]);
        let bw = u16::from_be_bytes([body[p + 8], body[p + 9]]);
        let bh = u16::from_be_bytes([body[p + 10], body[p + 11]]);
        if bw == 0 || bh == 0 { return None; }
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
    if msg.len() < 16 + 36 {
        return None;
    }
    let enc = i32::from_be_bytes(msg.get(12..16)?.try_into().ok()?);
    if enc != 0x44f {
        return None;
    }
    let body = &msg[msg.len() - 36..];
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&body[4..20]);
    iv.copy_from_slice(&body[20..36]);
    Some(record::unwrap_rekey(wrap, &key, &iv))
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

    #[tokio::test]
    async fn interrupted_record_read_keeps_partial_ciphertext() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let mut live = Live {
            tcp,
            layer: RecordLayer::new([1; 16], [2; 16]),
            width: 1, height: 1,
            video: Depacketizer::default(),
            srtp: None, udp: None, ctrl: None,
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
        let m = display_config(1920, 1080);
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
        assert_eq!(u32::from_be_bytes(m[d + 0x8a..d + 0x8e].try_into().unwrap()), 3840);
        assert_eq!(u32::from_be_bytes(m[d + 0x8e..d + 0x92].try_into().unwrap()), 2160);
        assert_eq!(u16::from_be_bytes(m[d + 0x92..d + 0x94].try_into().unwrap()), 0); // mode index < count
        assert_eq!(u32::from_be_bytes(m[d + 0x96..d + 0x9a].try_into().unwrap()), 7);
        assert_eq!(u16::from_be_bytes(m[d + 0x9a..d + 0x9c].try_into().unwrap()), 5);
        let mode = d + 0x9c;
        assert_eq!(u32::from_be_bytes(m[mode..mode + 4].try_into().unwrap()), 1920);
        assert_eq!(u32::from_be_bytes(m[mode + 4..mode + 8].try_into().unwrap()), 1080);
        assert_eq!(f64::from_be_bytes(m[mode + 16..mode + 24].try_into().unwrap()), 60.0);
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

