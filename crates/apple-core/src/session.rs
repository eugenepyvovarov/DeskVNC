//! One Apple Screen Sharing session.
//!
//! Cleartext through authentication and the prelude, then the record layer.
//! Video is H.264 over SRTP on UDP. Access units are handed to the shell as
//! `RectPayload::H264` for the webview's hardware decoder.

use std::time::Duration;

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
    let mut depay = std::mem::take(&mut session.video);
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
    // One resize round in flight at a time (§10.9): 0x1d → 0x451 → re-offer.
    // A second 0x1d sent mid-round races the encoder restart and stalls the
    // stream (observed live); later requests queue behind the current one.
    let mut resize_in_flight = false;
    let mut queued_resize: Option<(u16, u16)> = None;
    let video_task = tokio::spawn(async move {
        if let (Some(sock), Some(ctx)) = (udp, srtp.as_mut()) {
            let mut buf = vec![0u8; 65535];
            let mut cbuf = vec![0u8; 2048];
            let mut punch = tokio::time::interval(Duration::from_millis(200));
            let mut packets = 0u32;
            let mut opened = 0u32;
            let mut pictures = 0u32;
            let mut video_ssrc = None;
            let mut contexts = std::collections::HashMap::new();
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
                // A new SSRC is a new encoder (quality tier or resized
                // canvas): adopt the group immediately and restart the
                // depacketizer — the previous parameter sets are stale and
                // would reject every frame (RFC §10.9 receiver obligations).
                // Waiting for a config datagram instead black-screens forever
                // the moment that one UDP packet is lost.
                if video_ssrc != Some(ssrc) {
                    if contexts.len() >= 32 && !contexts.contains_key(&ssrc) {
                        continue;
                    }
                    video_ssrc = Some(ssrc);
                    depay = Depacketizer::default();
                }
                let receiver = contexts.entry(ssrc).or_insert_with(|| ctx.clone());
                let Some(rtp) = receiver.unprotect(&buf[..n]) else {
                    if packets <= 3 {
                        tracing::debug!("SRTP authentication rejected");
                    }
                    continue;
                };
                opened += 1;
                if opened == 1 {
                    tracing::info!(payload_type = rtp.payload_type, "Apple SRTP video authenticated");
                }
                let Some(au) = depay.push(rtp.timestamp, rtp.marker, &rtp.payload) else { continue };
                pictures += 1;
                if pictures <= 5 || (pictures <= 60 && au.keyframe) {
                    tracing::info!(pictures, bytes = au.annex_b.len(), keyframe = au.keyframe, "Apple H.264 picture");
                }
                let dimensions = video_dimensions.load(std::sync::atomic::Ordering::Relaxed);
                let rect = DecodedRect {
                    rect: Rect::new(0, 0, (dimensions >> 16) as u16, dimensions as u16),
                    payload: RectPayload::H264 {
                        data: au.annex_b,
                        flags: 0,
                        context_id: 0,
                        reset: au.keyframe,
                        keyframe: au.keyframe,
                    },
                };
                if emit(
                    &events2,
                    SessionEvent::FramebufferUpdate {
                        damage: rect.rect,
                        rects: vec![rect],
                    },
                )
                .await
                .is_err()
                {
                    break;
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
                        if target != (session.width, session.height) {
                            if resize_in_flight {
                                queued_resize = Some(target);
                            } else {
                                session.send_body(&display_config(target.0, target.1)).await?;
                                resize_in_flight = true;
                                tracing::info!(w = target.0, h = target.1, "Apple quality preset: resize requested");
                            }
                        }
                    }
                    Some(ClientCommand::MacDisplay(action)) => {
                        use remote_core::{MacDisplayAction, ProtocolEvent};
                        let changes_mode = !matches!(action, MacDisplayAction::List);
                        let result = async {
                            if display.is_none() {
                                let verifier = host_keys.clone().ok_or_else(|| "Mac display controls require the application's SSH host-key store".to_owned())?;
                                display = Some(crate::macos::DisplayController::connect(host, username, password, verifier).await?);
                            }
                            if changes_mode { queued_resize = None; }
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
                            session.send_body(&framebuffer_request(session.width, session.height)).await?;
                        }
                        emit(events, SessionEvent::Protocol(ProtocolEvent::AppleDisplay(result))).await.ok();
                    }
                    Some(ClientCommand::RequestResize { width, height }) => {
                        // In-band dynamic resize (RFC §10.9): 0x1d now, and the
                        // 0x451 that answers it drives the media re-offer.
                        if (640..=3840).contains(&width) && (480..=2160).contains(&height) {
                            if resize_in_flight {
                                queued_resize = Some((width, height));
                            } else {
                                session.send_body(&display_config(width, height)).await?;
                                resize_in_flight = true;
                                tracing::info!(width, height, "Apple display resize requested");
                            }
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
                    if resize_in_flight {
                        // §10.9 step 3: the re-offer is what restarts the
                        // encoder at the new canvas. Keys are reused.
                        resize_in_flight = false;
                        session.send_body(&offer).await?;
                        tracing::info!(bw, bh, "Apple display layout applied; media re-offered");
                        // The newest request wins; send it now that the round
                        // that was in flight has completed.
                        if let Some((w, h)) = queued_resize.take() {
                            if (w, h) != (session.width, session.height) {
                                session.send_body(&display_config(w, h)).await?;
                                resize_in_flight = true;
                                tracing::info!(w, h, "Apple queued resize sent");
                            }
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
}

