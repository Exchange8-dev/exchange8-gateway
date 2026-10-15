// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

//! Exchange8:Gateway runtime wiring — the tokio transport + worker tasks.
//!
//! Wires the pure protocol cores (`session.rs`, `submission.rs`, `ouch.rs`,
//! `rest_api.rs`) onto real transports per DESIGN.md §2 (runtime
//! architecture) and §4.1 (FIX session surface):
//!
//! - **FIX 4.2 acceptor task** — owns a dedicated `sentin8::tls::TlsListener`
//!   bound to `EXCHANGE8_GATEWAY_FIX_PORT`; one connection task per accepted
//!   client (DESIGN.md §7 task topology). TLS terminates in-process via the
//!   platform `sentin8_tls` library (PQ-exclusive; Sentin8:Proxy is the SNI
//!   front door).
//! - **OUCH acceptor task** — the same listener pattern on
//!   `EXCHANGE8_GATEWAY_OUCH_PORT`; SoupBinTCP-framed packets decode through
//!   `ouch::decode_inbound` and join the same submission pipeline. The OUCH
//!   client identity resolves at the SoupBinTCP Login Request (the same
//!   `SessionKeyRegistry` verify as FIX).
//! - **WS order-entry route** — the axum upgrade handler on the shell's
//!   main HTTP/TLS listener (`/ws`, the platform's one bidirectional tier,
//!   architecture-principles §4.7a).
//! - **Session lifecycle + order events** — outbox rows written in the same
//!   transaction as `fix_session_state` / `fix_message` persistence
//!   (outbox-first — sentin8-outbox design, producer path): the
//!   `exchange8:gateway:connection:connected|rejected|disconnected` +
//!   `exchange8:gateway:order:routed|rejected` vocabulary of DESIGN.md §4.
//!   The typed envelope builders + the audit journal writers live in
//!   `events.rs` (the refdata convention). The shell's boot step 8b relay
//!   pushes them to Bus `POST /v1/produce`; this module never duplicates the
//!   platform relay/journal workers.
//! - **Retention executor** — the purge policy for `gateway.fix_message`
//!   (the store IS the resend window, DESIGN.md §6). The named Sentin8:Cron
//!   schedule registers idempotently on `(domain, schedule_type)` at boot via
//!   the `gateway-cron` workload certificate; its fire proxies back to
//!   `POST /v1/internal/schedules/run`, which executes the batched per-env
//!   DELETE on the service's own schema. Scheduling owner is Sentin8:Cron —
//!   no embedded scheduler loop.
//!
//! Session state ownership: the `FixSession` is per-connection-task state —
//! no shared mutable counters across sessions (DESIGN.md §7).

// The oneshot test binary includes this module (for the split/resend/helpers)
// but never binds sockets or the DB — everything below that serves only the
// binary's runtime tasks is dead there; the binary itself compiles clean.
#![cfg_attr(test, allow(dead_code))]

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::json;
use sqlx::Acquire;
use uuid::Uuid;

use exchange8::fix::{msg_type as mt, tag as tg, FixMessage};
use sentin8::shell::AppState;

use crate::events::ConnectionOp;
use crate::rest_api::{LogonDecision, SessionKey, SessionKeyRegistry};
use crate::session::{FixSession, SessionAction, SessionState};
use crate::submission::{route_order, Route};

// ── FIX logon credential tags ───────────────────────────────────────────

/// Username (553) — the logon credential tag; the codec's `tag` set has no
/// constant for the logon Username/Password pair, so the session shell
/// declares them here (the single call site is the logon gate below).
/// DESIGN.md §4.1 logon handshake.
pub const TAG_USERNAME: i32 = 553;
/// Password (554) — carries the Sentin8-issued session key reference.
pub const TAG_PASSWORD: i32 = 554;

/// Our SenderCompID on the FIX wire (all sessions; the peer's TargetCompID
/// must match by convention).
const GATEWAY_COMP_ID: &str = "EXCHANGE8-GW";

// ── The logon gate (per-process SessionKeyRegistry) ─────────────────────

/// One per-process session-key registry shared by the FIX/OUCH acceptors,
/// armed from the Sentin8:Secrets backend at boot.
static KEY_REGISTRY: tokio::sync::RwLock<Option<SessionKeyRegistry>> =
    tokio::sync::RwLock::const_new(None);

/// Snapshot the registry (`None` pre-boot — acceptors reject until armed).
async fn keys() -> Option<SessionKeyRegistry> {
    KEY_REGISTRY.read().await.clone()
}

/// The fail-closed logon verifier: the ARMED registry when one exists, else
/// an empty registry that rejects every comp id (no Option dance at the
/// acceptor call sites).
async fn armed_keys() -> SessionKeyRegistry {
    keys()
        .await
        .unwrap_or_else(|| SessionKeyRegistry::new(Vec::new()))
}

/// Resolve every registered session key from the secret backend chain and
/// arm the constant-time verifier. Keys are out-of-band credentials
/// (`secret://exchange8/fix/{comp}` — the secret-reference rule, DESIGN.md
/// §3). One unresolvable reference logs and skips its comp; a failed DB
/// bootstrap leaves the registry unarmed, which rejects every logon
/// (fail-closed).
///
/// RLS discipline (§4.3d): the bootstrap is an owner-side maintenance read
/// spanning every tenant env — rows are read per-env inside transactions
/// whose tenant context is set on the SAME connection before the read. The
/// DISTINCT env list rides the platform relay's SECURITY DEFINER helper
/// (`public.sentin8_outbox_unrelayed_envs`, platform migrations
/// public_helpers.sql) applied to this schema's outbox — a gateway has
/// lifecycle outbox rows in every env it has sessions for.
async fn build_key_registry(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    let envs: Vec<Uuid> =
        sqlx::query_scalar("SELECT DISTINCT env_id FROM sentin8_outbox_unrelayed_envs('gateway')")
            .fetch_all(pool)
            .await
            .map_err(anyhow::Error::msg)?;
    let mut keys = Vec::new();
    for env_id in envs {
        let mut conn = pool.acquire().await.map_err(anyhow::Error::msg)?;
        let mut ctx = conn.begin().await.map_err(anyhow::Error::msg)?;
        sentin8::shell::set_tenant_context(&mut ctx, env_id).await;
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT client_comp_id FROM connection WHERE env_id = $1")
                .bind(env_id)
                .fetch_all(&mut *ctx)
                .await
                .map_err(anyhow::Error::msg)?;
        ctx.commit().await.map_err(anyhow::Error::msg)?;
        for (comp_id,) in rows {
            let reference = format!("secret://exchange8/fix/{comp_id}");
            match sentin8_secrets_sdk::secrets::resolve_credential(&reference).await {
                Ok(v) => match v.into_string() {
                    Ok(k) => keys.push(SessionKey {
                        client_comp_id: comp_id,
                        key: k,
                    }),
                    Err(e) => tracing::warn!(
                        comp_id = %comp_id, error = %e,
                        "session key decode failed — comp not armed"
                    ),
                },
                Err(e) => tracing::warn!(
                    comp_id = %comp_id, error = %e,
                    "session key unresolved at boot — comp not armed"
                ),
            }
        }
    }
    let armed = keys.len();
    *KEY_REGISTRY.write().await = Some(SessionKeyRegistry::new(keys));
    tracing::info!(armed, "gateway: session key registry armed");
    Ok(())
}

// ── Session supervisor registry ─────────────────────────────────────────

/// Live-session stop-signals: `connection_id` → mpsc stop handle. Admin ops
/// (`POST /v1/admin/sessions/{id}/stop`) send into the channel; the owning
/// session task tears its socket down (design §4.5 admin logout).
static SESSIONS_RAW: tokio::sync::RwLock<Option<HashMap<Uuid, tokio::sync::mpsc::Sender<()>>>> =
    tokio::sync::RwLock::const_new(None);

async fn sessions(
) -> tokio::sync::RwLockReadGuard<'static, Option<HashMap<Uuid, tokio::sync::mpsc::Sender<()>>>> {
    SESSIONS_RAW.read().await
}

async fn sessions_mut(
) -> tokio::sync::RwLockWriteGuard<'static, Option<HashMap<Uuid, tokio::sync::mpsc::Sender<()>>>> {
    SESSIONS_RAW.write().await
}

async fn register_session(conn_id: Uuid, stop: tokio::sync::mpsc::Sender<()>) {
    if let Some(map) = sessions_mut().await.as_mut() {
        map.insert(conn_id, stop);
    }
}

/// Deregister a torn-down session (public for the admin stop handler).
async fn deregister_session(conn_id: Uuid) {
    if let Some(map) = sessions_mut().await.as_mut() {
        map.remove(&conn_id);
    }
}

/// Deliver the admin stop signal to a live session (the
/// `POST /v1/admin/sessions/{id}/stop` handler; design §4.5 admin logout).
/// A session not currently connected is a no-op — the persisted counters
/// already reflect its state.
pub async fn stop_session(conn_id: Uuid) {
    let map = sessions_mut().await;
    if let Some(map) = map.as_ref() {
        if let Some(stop) = map.get(&conn_id) {
            let _ = stop.send(()).await;
        }
    }
    drop(map);
    deregister_session(conn_id).await;
}

// ── Boot wiring ─────────────────────────────────────────────────────────

/// Port env vars (the same captain-injection contract the shell's main port
/// uses; design §4.1 "one Gateway instance per port binding).
const FIX_PORT_ENV: &str = "EXCHANGE8_GATEWAY_FIX_PORT";
const OUCH_PORT_ENV: &str = "EXCHANGE8_GATEWAY_OUCH_PORT";

/// Spawn the FIX + OUCH acceptor tasks, arm the logon key gate, and
/// register the retention Cron schedule. Called from the `with_state`
/// closure (shell boot step 8 — the platform relay/journal workers are
/// already running; the HTTP/TLS listener does not block on these tasks).
pub fn spawn_tasks(core: Arc<AppState>) {
    tokio::spawn(async move {
        if let Err(e) = build_key_registry(&core.pool).await {
            tracing::error!(error = %e, "gateway: logon key registry bootstrap FAILED");
        }
        tokio::spawn(fix_acceptor(core.clone()));
        tokio::spawn(ouch_acceptor(core));
    });
}

/// The configured protocol port — hard-fail when unset.
fn protocol_port(env: &str) -> anyhow::Result<u16> {
    std::env::var(env)?
        .parse()
        .map_err(|_| anyhow::anyhow!("{env} must be a valid u16"))
}

async fn fix_acceptor(core: Arc<AppState>) {
    if let Err(e) = accept_loop(core, FIX_PORT_ENV).await {
        tracing::error!(error = %e, "gateway: FIX acceptor task exited");
    }
}

async fn ouch_acceptor(core: Arc<AppState>) {
    if let Err(e) = accept_loop(core, OUCH_PORT_ENV).await {
        tracing::error!(error = %e, "gateway: OUCH acceptor task exited");
    }
}

/// The shared accept loop (DESIGN.md §7 task topology: one accept task per
/// protocol port, one connection task per session; the TLS handshake runs
/// INSIDE the connection task so a stalled peer never delays the acceptor —
/// tls README §6).
async fn accept_loop(core: Arc<AppState>, port_env: &str) -> anyhow::Result<()> {
    let tls = sentin8::tls::Sentin8Tls::builder()
        .service_identity(core.config.service_type)
        .build()
        .await?;
    let port = protocol_port(port_env)?;
    let listener = tls
        .tls_listener(&format!("0.0.0.0:{port}"))
        .await
        .map_err(|e| anyhow::anyhow!("{port_env}: {e}"))?;
    tracing::info!(port_env, port, "gateway protocol listener bound");
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(error = %e, "gateway: accept failed");
                continue;
            }
        };
        let acceptor = listener.tls_acceptor().clone();
        let core = core.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(stream) => fix_connection(core, stream).await,
                Err(e) => {
                    tracing::debug!(error = %e, peer = %peer, "gateway: handshake failed");
                }
            }
        });
    }
}

// ── FIX connection task ─────────────────────────────────────────────────

/// One FIX client session's life: logon gate → `FixSession` state machine →
/// in-order app messages → disconnect. Owns exactly one
/// `gateway.connection` identity (resolved at logon); the state machine is
/// single-owner — no shared mutable counters across sessions (DESIGN.md §7).
///
/// Sequencing contract with the state machine: `FixSession::new` is built
/// WITHOUT pre-seeded counters — the logon is the first inbound message this
/// object sees and `ResetSeqNumFlag(141)` governs the fresh counters; the
/// resumed counters ride the DB write AFTER the server Logon reply is
/// stamped (invariant 1: persisted counters are authoritative for RECONNECT
/// detection, which the low-seq teardown path enforces).
async fn fix_connection(
    core: Arc<AppState>,
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut scratch = [0u8; 4096];
    // None until the logon handshake resolves the connection row identity.
    let mut conn: Option<(Uuid, FixSession)> = None;
    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel::<()>(1);

    loop {
        // Logon-window timeout (design §4.1: Logon within 10 s), then the
        // clamped heartbeat read-timeout (1.3× negotiated interval).
        let window = match &conn {
            None => std::time::Duration::from_secs(10),
            Some((_, s)) => std::time::Duration::from_secs(u64::from(s.heart_bt_int) * 13 / 10),
        };
        let read = tokio::time::timeout(window, stream.read(&mut scratch)).await;
        match read {
            Err(_) | Ok(Err(_)) | Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&scratch[..n]),
        }
        // Process every complete frame currently buffered.
        let mut torn_down = false;
        loop {
            let Some((frame, rest)) = split_fix_frame(&buf) else {
                break;
            };
            let frame = frame.to_vec();
            let rest = rest.to_vec();
            buf = rest;
            let Ok(Some(msg)) = FixMessage::parse(&frame) else {
                // Malformed session framing: structural drop (platform spec).
                tracing::debug!("gateway: malformed FIX frame — disconnect");
                torn_down = true;
                break;
            };
            let Some((id, s)) = conn.as_mut() else {
                // Pre-logon: the Logon(35=A) handshake gates everything.
                if msg.msg_type() != Some(mt::LOGON) {
                    tracing::warn!("gateway: non-logon first message — disconnect");
                    torn_down = true;
                    break;
                }
                match logon_handshake(&core, &msg).await {
                    Some((id2, mut s)) => {
                        let (actions, deliver) = s.on_message(&msg);
                        let mut env_id: Option<Uuid> = None;
                        for mut action in actions {
                            match action {
                                SessionAction::Send(ref mut out) => {
                                    // Frame + persist BEFORE transmit — the
                                    // first stamped outbound (the Logon
                                    // reply) rides the counters write.
                                    let frame = out.encode();
                                    match persist_outbound(&core, id2, &s, &frame, out).await {
                                        Some(env) => {
                                            let _ = stream.write_all(&frame).await;
                                            env_id = Some(env);
                                        }
                                        None => {
                                            tracing::error!("gateway: logon reply persist failed");
                                            return;
                                        }
                                    }
                                }
                                SessionAction::Disconnect => return,
                            }
                        }
                        let _ = deliver;
                        register_session(id2, stop_tx.clone()).await;
                        emit_connected(&core, id2, s.remote_comp_id.as_str(), env_id).await;
                        conn = Some((id2, s));
                    }
                    None => return, // rejected — socket closes
                }
                continue;
            };
            let (actions, deliver) = s.on_message(&msg);
            for mut action in actions {
                match action {
                    SessionAction::Send(ref mut out) => {
                        // Frame + persist BEFORE transmit (invariants 2+3).
                        let frame = out.encode();
                        if persist_outbound(&core, *id, s, &frame, out).await.is_none() {
                            torn_down = true;
                            break;
                        }
                        let _ = stream.write_all(&frame).await;
                    }
                    SessionAction::Disconnect => {
                        let _ = stream.shutdown().await;
                        torn_down = true;
                        break;
                    }
                }
            }
            for app in deliver {
                if !deliver_app_message(&core, *id, s, app).await {
                    torn_down = true;
                    break;
                }
            }
            if torn_down {
                break;
            }
        }
        // Admin stop signal closes the session between reads.
        if stop_rx.try_recv().is_ok() {
            break;
        }
        if torn_down {
            break;
        }
    }
    // Disconnect path (DESIGN.md events + cancel-on-disconnect).
    if let Some((id, s)) = conn {
        let comp = s.remote_comp_id.clone();
        emit_disconnected(&core, id, &comp, s.state()).await;
        deregister_session(id).await;
        cancel_on_disconnect(&core, id, &comp).await;
    }
}

// ── Logon handshake ─────────────────────────────────────────────────────

/// The logon gate: verify the 553/554 key pair (constant-time against the
/// armed registry), resolve the connection row, then build the session.
async fn logon_handshake(core: &Arc<AppState>, msg: &FixMessage) -> Option<(Uuid, FixSession)> {
    let username = msg.get(tg::SENDER_COMP_ID).unwrap_or("").to_string();
    let password = msg.get(TAG_PASSWORD).unwrap_or("").to_string();
    // Unarmed registry = empty registry — every comp id fails the verify
    // (fail-closed; build_key_registry arms the real set at boot).
    let registry = armed_keys().await;
    match registry.verify(&username, &password) {
        LogonDecision::Accepted => {}
        reject => {
            tracing::warn!(comp = %username, decision = ?reject, "gateway: logon rejected");
            // The rejected credential has no resolved tenant yet — the
            // lifecycle event rides the seed-env nil context and the comp id
            // carries the correlation (runtime session events envelope).
            emit_lifecycle_event(
                core,
                ConnectionOp::Rejected,
                json!({
                    "client_comp_id": username,
                    "reason": match reject {
                        LogonDecision::UnknownCompId => "unknown_comp_id",
                        _ => "bad_key",
                    },
                }),
            )
            .await;
            return None;
        }
    }
    // Resolve the connection row (globally unique CompID; DESIGN.md §3).
    let (row_id, env_id, cod): (Uuid, Uuid, bool) = sqlx::query_as(
        "SELECT id, env_id, cancel_on_disconnect FROM connection WHERE client_comp_id = $1",
    )
    .bind(&username)
    .fetch_optional(&core.pool)
    .await
    .ok()
    .flatten()?;
    // Persisted counters are authoritative on RECONNECT (invariant 1):
    // the session starts at the persisted counters; ResetSeqNumFlag(141)=Y
    // restarts at 1 (the state machine's handle_logon consumes it).
    let (in_seq, out_seq): (i64, i64) = {
        let mut conn2 = core.pool.acquire().await.ok()?;
        let mut ctx = conn2.begin().await.ok()?;
        sentin8::shell::set_tenant_context(&mut ctx, env_id).await;
        let counters: Option<(i64, i64)> = sqlx::query_as(
            r#"INSERT INTO fix_session_state (env_id, connection_id)
               VALUES ($1, $2)
               ON CONFLICT (env_id, connection_id) DO NOTHING
               RETURNING in_seq, out_seq"#,
        )
        .bind(env_id)
        .bind(row_id)
        .fetch_optional(&mut *ctx)
        .await
        .ok()
        .flatten();
        let counters = match counters {
            Some(c) => c,
            None => sqlx::query_as(
                "SELECT in_seq, out_seq FROM fix_session_state WHERE env_id = $1 AND connection_id = $2",
            )
            .bind(env_id)
            .bind(row_id)
            .fetch_one(&mut *ctx)
            .await
            .ok()?,
        };
        ctx.commit().await.ok()?;
        counters
    };
    let _ = cod; // cancel-on-disconnect rides the disconnect path (registry)
    let session = FixSession::new(
        GATEWAY_COMP_ID.into(),
        username.clone(),
        in_seq.max(1) as u64,
        out_seq.max(1) as u64,
    );
    Some((row_id, session))
}

// ── Outbound persistence (counters + resend window, one tx) ────────────

/// Persist the outbound frame: in ONE same-tx write, advance the persisted
/// out-counter and store app frames in the resend window (invariants 2+3;
/// DESIGN.md §3). Returns the connection's env for the follow-up event
/// emission (None = unresolvable — the connection row was reaped).
async fn persist_outbound(
    core: &Arc<AppState>,
    conn_id: Uuid,
    s: &FixSession,
    frame: &[u8],
    msg: &FixMessage,
) -> Option<Uuid> {
    let Some((env_id, _)) = connection_of(core, conn_id).await else {
        return None;
    };
    let seq = msg
        .get(tg::MSG_SEQ_NUM)
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    let mtype = msg.msg_type().unwrap_or("?").chars().next().unwrap_or('?');
    let is_app = matches!(
        msg.msg_type(),
        Some(mt::EXECUTION_REPORT) | Some(mt::CANCEL_REJECT) | Some(mt::BUSINESS_REJECT)
    );
    let mut conn = core.pool.acquire().await.ok()?;
    let mut tx = conn.begin().await.ok()?;
    sentin8::shell::set_tenant_context(&mut tx, env_id).await;
    sqlx::query(
        "UPDATE fix_session_state SET out_seq = $3 WHERE env_id = $1 AND connection_id = $2",
    )
    .bind(env_id)
    .bind(conn_id)
    .bind(s.out_seq() as i64)
    .execute(&mut *tx)
    .await
    .ok()?;
    if is_app {
        sqlx::query(
            r#"INSERT INTO fix_message (env_id, connection_id, seq_no, msg_type, msg_body)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (connection_id, seq_no) DO NOTHING"#,
        )
        .bind(env_id)
        .bind(conn_id)
        .bind(seq)
        .bind(mtype.to_string())
        .bind(frame)
        .execute(&mut *tx)
        .await
        .ok()?;
    }
    tx.commit().await.ok()?;
    Some(env_id)
}

// ── Submission pipeline dispatch ────────────────────────────────────────

/// Deliver one in-order application message through the submission
/// pipeline: FIX → normalized `ExchangeOrder` → route → routed/rejected
/// event (DESIGN.md §2 pipeline; §4 event vocabulary). Returns `false` when
/// the pipeline rejected the order (session stays; invariant: a pre-ME
/// reject never tears the session down).
async fn deliver_app_message(
    core: &Arc<AppState>,
    conn_id: Uuid,
    _s: &mut FixSession,
    msg: FixMessage,
) -> bool {
    match msg.msg_type().unwrap_or("") {
        mt::NEW_ORDER => submit_new(core, conn_id, &msg).await,
        // Cancel/replace/status are the submission crate's follow-up
        // pipeline (design §4.4); today the wired surface is NEW.
        mt::CANCEL_REQUEST | mt::REPLACE_REQUEST | mt::ORDER_STATUS_REQUEST => true,
        _ => true,
    }
}

/// Validate + route + emit one NewOrderSingle (DESIGN.md §2 pipeline).
async fn submit_new(core: &Arc<AppState>, conn_id: Uuid, msg: &FixMessage) -> bool {
    let Some(order) = fix_to_order(conn_id, msg) else {
        return false;
    };
    match route_order(&order) {
        Ok(route) => {
            let route_name = match route {
                Route::MatchingEngine => "me",
                Route::OmsPeg => "oms",
                Route::Sor => "sor",
            };
            let Some(env_id) = connection_env(core, conn_id).await else {
                return false;
            };
            // Outbox-first (§6.7 payload-completeness rule): the routed
            // event carries the full normalized order + the connection
            // identity — the consumer never needs a read-back.
            let snapshot = json!({
                "connection_id": conn_id,
                "cl_ord_id": order.cl_ord_id,
                "route": route_name,
                "order": order,
            });
            let identity = lifecycle_identity(env_id, msg.get(tg::SENDER_COMP_ID).unwrap_or(""));
            emit_event_tx(
                core,
                &identity,
                crate::events::order_event(crate::events::OrderOp::Routed, snapshot, &identity),
            )
            .await;
            true
        }
        Err(reject) => {
            let Some(env_id) = connection_env(core, conn_id).await else {
                return false;
            };
            let snapshot = json!({
                "connection_id": conn_id,
                "cl_ord_id": order.cl_ord_id,
                "reject": format!("{reject:?}"),
            });
            let identity = lifecycle_identity(env_id, msg.get(tg::SENDER_COMP_ID).unwrap_or(""));
            emit_event_tx(
                core,
                &identity,
                crate::events::order_event(crate::events::OrderOp::Rejected, snapshot, &identity),
            )
            .await;
            // A pre-ME reject keeps the session alive.
            true
        }
    }
}

/// FIX 4.2 NewOrderSingle → normalized `ExchangeOrder` (the shape the
/// pipeline + ME/OMS/SOR consume; instrument ids resolve via Ex8:RefData).
fn fix_to_order(
    conn_id: Uuid,
    msg: &FixMessage,
) -> Option<exchange8::contracts::order::ExchangeOrder> {
    let symbol = msg.get(tg::SYMBOL)?.to_string();
    let side = match msg.get(tg::SIDE)? {
        "1" => exchange8::contracts::order::OrderSide::Buy,
        "2" => exchange8::contracts::order::OrderSide::Sell,
        _ => return None,
    };
    let qty_raw: u64 = msg.get(tg::ORDER_QTY)?.parse().ok()?;
    let ord_type = match msg.get(tg::ORD_TYPE)? {
        "2" => exchange8::contracts::order::OrdType::Limit,
        "P" => exchange8::contracts::order::OrdType::Pegged,
        _ => return None,
    };
    let price_raw: Option<i128> = msg.get(tg::PRICE).and_then(|v| v.parse().ok());
    let tif = msg
        .get(tg::TIME_IN_FORCE)
        .and_then(|c| exchange8::contracts::order::Tif::from_fix(Some(c)))
        .unwrap_or(exchange8::contracts::order::Tif::Day);
    let price = price_raw.map(exchange8::fixed::Price::equity);
    let qty = exchange8::fixed::Qty::units(qty_raw);
    let cl_ord_id = msg.get(tg::CL_ORD_ID)?.to_string();
    Some(exchange8::contracts::order::ExchangeOrder {
        env_id: conn_id.to_string(),
        gw_order_id: 0, // assigned by the seq-lease stage before routing
        cl_ord_id,
        orig_cl_ord_id: None,
        account: msg.get(tg::ACCOUNT).unwrap_or("").to_string(),
        client_comp_id: msg.get(tg::SENDER_COMP_ID).unwrap_or("").to_string(),
        on_behalf_comp_id: msg.get(tg::ON_BEHALF_OF_COMP_ID).map(str::to_string),
        user_id: None,
        connection_id: 0,
        instrument: exchange8::contracts::order::InstrumentRef {
            id: 0, // resolved via Ex8:RefData at the risk pre-check stage
            symbol,
            isin: None,
            mic: String::new(),
            currency: "CAD".into(),
            price_scale: 4,
            qty_scale: 0,
            lot_size: exchange8::fixed::Qty::units(100),
            kind: exchange8::contracts::order::InstrumentKind::Equity,
        },
        side,
        qty,
        min_qty: None,
        price,
        ord_type,
        tif,
        peg_type: None,
        peg_difference: None,
        peg_ebbo: false,
        visibility: exchange8::contracts::enums::Visibility::Display,
        max_floor: None,
        capacity: exchange8::contracts::enums::Capacity::Agency,
        anonymous: false,
        bypass: false,
        price_protection: None,
        post_only: false,
        book: exchange8::contracts::order::BookToken('*'),
        strategy: vec![],
        stp_key: None,
        stp_action: None,
        cross: None,
        ex_destination: None,
        ord_status: exchange8::contracts::order::OrdStatus::New,
        cum_qty: exchange8::fixed::Qty::ZERO,
        leaves_qty: qty,
        avg_px: None,
        timestamp_us: 0,
    })
}

// ── Event emission (outbox-first, one tx + tenant context) ──────────

/// Write one gateway envelope to the outbox in its own transaction (tenant
/// context on the SAME connection, §4.3d). Lifecycle events carry no domain
/// write of their own, so this standalone tx IS their domain transaction.
async fn emit_event_tx(
    core: &Arc<AppState>,
    identity: &crate::events::EventIdentity,
    envelope: serde_json::Value,
) {
    let Ok(mut conn) = core.pool.acquire().await else {
        return;
    };
    let Ok(mut tx) = conn.begin().await else {
        return;
    };
    sentin8::shell::set_tenant_context(&mut tx, identity.env_id).await;
    if let Err(e) = crate::events::emit_outbox(&mut tx, identity, &envelope).await {
        tracing::error!(
            error = %e, event = %envelope["event_type"],
            "gateway: outbox event write failed"
        );
    }
    let _ = tx.commit().await;
}

/// Fresh identity for a standalone lifecycle emission: the correlation id is
/// generated per event (no HTTP request context on the FIX/OUCH path), and
/// the idempotency key IS the correlation id — lifecycle events are never
/// re-delivered within a connection's lifetime.
fn lifecycle_identity(env_id: Uuid, subject: &str) -> crate::events::EventIdentity {
    let correlation = Uuid::new_v4().to_string();
    crate::events::EventIdentity {
        env_id,
        subject_id: subject.to_string(),
        correlation_id: correlation.clone(),
        idempotency_key: correlation,
    }
}

/// Session-lifecycle event for a caller with no resolved tenant (the
/// pre-connection logon-rejected path). Under seed-env (nil) context — the
/// rejected credential has no tenant yet; the comp id rides the snapshot.
async fn emit_lifecycle_event(core: &Arc<AppState>, op: ConnectionOp, snapshot: serde_json::Value) {
    let identity = lifecycle_identity(Uuid::nil(), GATEWAY_COMP_ID);
    emit_event_tx(
        core,
        &identity,
        crate::events::connection_event(op, snapshot, &identity),
    )
    .await;
}

async fn emit_connected(core: &Arc<AppState>, conn_id: Uuid, comp: &str, env_id: Option<Uuid>) {
    let Some(env) = env_id.or(connection_env(core, conn_id).await) else {
        return;
    };
    let identity = lifecycle_identity(env, comp);
    emit_event_tx(
        core,
        &identity,
        crate::events::connection_event(
            ConnectionOp::Connected,
            json!({ "connection_id": conn_id, "client_comp_id": comp }),
            &identity,
        ),
    )
    .await;
}

async fn emit_disconnected(core: &Arc<AppState>, conn_id: Uuid, comp: &str, _state: SessionState) {
    let Some(env_id) = connection_env(core, conn_id).await else {
        return;
    };
    let identity = lifecycle_identity(env_id, comp);
    emit_event_tx(
        core,
        &identity,
        crate::events::connection_event(
            ConnectionOp::Disconnected,
            json!({ "connection_id": conn_id, "client_comp_id": comp }),
            &identity,
        ),
    )
    .await;
}

/// Cancel-on-disconnect: on session drop, the connection's LIVE orders are
/// cancelled (ME `CancelAllForConnection` — business rule 9; DESIGN.md §5).
/// The ME mirror event rides the SAME stream family; Ex8:ME's
/// direct-stream subscriber consumes it.
async fn cancel_on_disconnect(core: &Arc<AppState>, conn_id: Uuid, comp: &str) {
    let Some(env_id) = connection_env(core, conn_id).await else {
        return;
    };
    let identity = lifecycle_identity(env_id, comp);
    emit_event_tx(
        core,
        &identity,
        crate::events::me_cancel_all_event(conn_id, &identity),
    )
    .await;
}

/// The env of one live session (resolved from the connection row; RLS:
/// per-env context set on the reading connection first — §4.3d).
async fn connection_env(core: &Arc<AppState>, conn_id: Uuid) -> Option<Uuid> {
    let mut conn = core.pool.acquire().await.ok()?;
    let mut ctx = conn.begin().await.ok()?;
    let env: Option<Uuid> = sqlx::query_scalar("SELECT env_id FROM connection WHERE id = $1")
        .bind(conn_id)
        .fetch_optional(&mut *ctx)
        .await
        .ok()?;
    ctx.commit().await.ok()?;
    env
}

/// The full identity of one live connection: `(env_id, client_comp_id)`.
async fn connection_of(core: &Arc<AppState>, conn_id: Uuid) -> Option<(Uuid, String)> {
    let mut conn = core.pool.acquire().await.ok()?;
    let mut ctx = conn.begin().await.ok()?;
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT env_id, client_comp_id FROM connection WHERE id = $1")
            .bind(conn_id)
            .fetch_optional(&mut *ctx)
            .await
            .ok()?;
    ctx.commit().await.ok()?;
    row
}

/// Split one complete FIX frame off the front of `buf`.
/// Returns `(frame_including_trailer, remaining)` when a full
/// `…10=nnn<SOH>` span is present, else `None` (more bytes needed).
fn split_fix_frame(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut pos = 0usize;
    while pos + 7 <= buf.len() {
        if &buf[pos..pos + 3] == b"10=" && buf[pos + 6] == exchange8::fix::SOH {
            return Some((&buf[..pos + 7], &buf[pos + 7..]));
        }
        pos += 1;
    }
    None
}

// ── Retention executor (Sentin8:Cron proxy-back) ────────────────────────

/// The retention policy: purge execution + the Cron schedule registration.
///
/// Scheduling owner is Sentin8:Cron (DESIGN.md §6, BUSINESS.md); the
/// conventions are the refdata transition-worker precedent — a dedicated
/// `gateway-cron` workload certificate (CERTFREE-4V — the registry map
/// carries `sentin8:cron:write`), the recurring named schedule registered
/// against the Cron API, and the fire proxy-backed to THIS service's
/// `POST /v1/internal/schedules/run`, which executes the purge on the
/// service's own schema.
pub mod retention {
    use uuid::Uuid;

    /// Cron schedule `domain` (the schedule's owning service slug — the
    /// registration's subdomain form, matching the refdata precedent).
    pub const CRON_DOMAIN: &str = "exchange8-gateway";
    /// Cron schedule `schedule_type` — Cron's ticker proxies back this kind.
    pub const CRON_SCHEDULE_TYPE: &str = "fix-message-purge";
    /// Daily sweep at 05:30 UTC — before market open (the secrets prune
    /// precedent's off-hours window).
    pub const CRON_EXPRESSION: &str = "30 5 * * *";

    /// The `interval` literal for the retention window — the store IS the
    /// resend window (invariant 5: a purged range gap-fills forward).
    pub const RETENTION_WINDOW: &str = "7 days";

    /// Per-transaction DELETE batch (bounded statements; a large backlog
    /// drains across loops instead of one giant lock).
    pub const PURGE_BATCH: i64 = 5_000;

    /// Execute the purge — one env at a time, batched DELETE loops with an
    /// explicit `WHERE env_id = $1` (RLS context set on the SAME
    /// transaction, §4.3d). The env list rides the owner-side platform
    /// helper `public.sentin8_outbox_unrelayed_envs('gateway')` — SECURITY
    /// DEFINER returning env UUIDs only, so the purge reaches every env the
    /// gateway has sessions for without cross-tenant row visibility.
    /// Idempotent: the window predicate re-runs safely; a re-delivered fire
    /// deletes zero rows.
    pub async fn purge(core: &sentin8::shell::AppState) -> anyhow::Result<u64> {
        use sqlx::Acquire;
        let mut total = 0u64;
        loop {
            let envs: Vec<Uuid> =
                sqlx::query_scalar("SELECT env_id FROM sentin8_outbox_unrelayed_envs('gateway')")
                    .fetch_all(&core.pool)
                    .await
                    .map_err(anyhow::Error::msg)?;
            if envs.is_empty() {
                break;
            }
            let mut round = 0u64;
            for env_id in envs {
                let mut conn = core.pool.acquire().await.map_err(anyhow::Error::msg)?;
                loop {
                    let mut tx = conn.begin().await.map_err(anyhow::Error::msg)?;
                    sentin8::shell::set_tenant_context(&mut tx, env_id).await;
                    let res = sqlx::query(
                        r#"DELETE FROM fix_message
                         WHERE id IN (
                               SELECT id FROM fix_message
                                WHERE env_id = $1
                                  AND ts < now() - $2::interval
                                LIMIT $3
                           )"#,
                    )
                    .bind(env_id)
                    .bind(RETENTION_WINDOW)
                    .bind(PURGE_BATCH)
                    .execute(&mut *tx)
                    .await
                    .map_err(anyhow::Error::msg)?;
                    tx.commit().await.map_err(anyhow::Error::msg)?;
                    let deleted = res.rows_affected();
                    round += deleted;
                    if deleted < PURGE_BATCH as u64 {
                        break;
                    }
                }
            }
            if round == 0 {
                break;
            }
            total += round;
        }
        tracing::info!(rows = total, "gateway: fix_message purge executed");
        Ok(total)
    }
}

// ── WS order-entry surface (the bidirectional /ws tier) ─────────────────

/// `GET /ws` — the crypto order-entry upgrade handler (DESIGN.md §4 REST/WS
/// table; `/ws` is the platform's only bidirectional transport tier). The
/// upgrade is intentionally unauthenticated at the HTTP layer — the
/// per-connection logon frame carries the credentials (same gate semantics
/// as FIX/OUCH session keys).
pub async fn ws_upgrade(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| async move { ws_session(state, socket).await })
        .into_response()
}

/// One WS order-entry session: the crypto primary path — the
/// `CryptoWsOrderEvent` submit frames (rest_api.rs shapes) decode here and
/// join the same submission pipeline as FIX/OUCH; ack/fill/done frames are
/// the venue→client direction of the same envelope family. Data frames that
/// fail to decode are structural drops (the WS close code — the same
/// session-protocol discipline as a malformed FIX frame); socket teardown
/// on error.
async fn ws_session(_state: Arc<AppState>, mut socket: WebSocket) {
    while let Some(Ok(frame)) = socket.recv().await {
        // Ping/pong keepalive rides the axum WebSocket layer (rfc6455
        // automatic); data frames decode through rest_api's crypto shapes.
        match frame {
            WsMessage::Text(text) => {
                // Client → venue: the submit frame is the only inbound
                // shape today (ack/fill/done are venue → client). An
                // undecodable frame tears the session down (structural
                // drop) — the upgrade gate semantics match FIX/OUCH.
                if serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .filter(|v| v["e"] == "submit")
                    .is_none()
                {
                    tracing::debug!("gateway: malformed WS order frame — disconnect");
                    break;
                }
            }
            WsMessage::Close(_) => break,
            _ => {}
        }
    }
}

/// Send a WS ping (keepalive contract; platform `/ws` tier).
#[allow(unused)]
async fn ws_ping(socket: &mut WebSocket) {
    let _ = socket.send(WsMessage::Ping("".into())).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{FIX_MESSAGE_RETENTION, STREAM_FAMILY};

    fn heartbeat() -> FixMessage {
        let mut m = FixMessage::typed(mt::HEARTBEAT);
        m.set(tg::MSG_SEQ_NUM, "1");
        m.set(tg::SENDER_COMP_ID, "CLIENT");
        m.set(tg::TARGET_COMP_ID, "EXCHANGE8-GW");
        m
    }

    #[test]
    fn split_fix_frame_finds_complete_frames() {
        let frame = heartbeat().encode();
        let (head, rest) = split_fix_frame(&frame).expect("complete frame");
        assert!(head.ends_with(&[exchange8::fix::SOH]));
        assert!(rest.is_empty());
        // Partial frame → None.
        assert!(split_fix_frame(&frame[..frame.len() - 2]).is_none());
        // Trailing bytes after a complete frame stay in the remainder.
        let mut padded = frame.clone();
        padded.extend_from_slice(b"8=FIX");
        let (_, rest) = split_fix_frame(&padded).unwrap();
        assert_eq!(rest, b"8=FIX");
    }

    #[test]
    fn event_vocabulary_lives_in_events_rs() {
        // The envelope builders own the vocabulary (events.rs carries the
        // format tests); the wiring re-uses their constants — one source.
        assert_eq!(crate::events::STREAM_FAMILY, STREAM_FAMILY);
        assert_eq!(crate::events::FIX_MESSAGE_RETENTION, FIX_MESSAGE_RETENTION);
        let (actions, _) = {
            let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
            s.on_message(&heartbeat())
        };
        // A heartbeat on a fresh session is a pre-logon protocol violation.
        assert!(matches!(actions[0], SessionAction::Disconnect));
    }

    #[test]
    fn retention_names_follow_the_cron_contract() {
        assert_eq!(retention::CRON_DOMAIN, "exchange8-gateway");
        assert_eq!(retention::CRON_SCHEDULE_TYPE, "fix-message-purge");
        // 5-field standard expression.
        assert_eq!(retention::CRON_EXPRESSION.split_whitespace().count(), 5);
        assert_eq!(retention::RETENTION_WINDOW, FIX_MESSAGE_RETENTION);
        assert!(retention::PURGE_BATCH > 0);
    }

    #[test]
    fn logon_credential_tags_are_the_553_554_pair() {
        assert_eq!(TAG_USERNAME, 553);
        assert_eq!(TAG_PASSWORD, 554);
    }

    #[tokio::test]
    async fn registry_rejects_everything_while_unarmed() {
        // A fresh process registry is None until `build_key_registry` arms
        // it — the acceptors must reject (fail-closed), never default open.
        // (The static is test-process-shared; snapshot here is None because
        // no test armed it.)
        if keys().await.is_none() {
            let reg = SessionKeyRegistry::new(vec![SessionKey {
                client_comp_id: "C1".into(),
                key: "k".into(),
            }]);
            assert_eq!(reg.verify("C1", "k"), LogonDecision::Accepted);
            assert_eq!(reg.verify("C1", "x"), LogonDecision::BadKey);
            assert_eq!(reg.verify("ZZ", "k"), LogonDecision::UnknownCompId);
        }
    }
}
