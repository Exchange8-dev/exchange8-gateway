// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

//! Exchange8:Gateway typed event envelopes (DBX producer path).
//!
//! Every gateway lifecycle/order write pairs the domain persistence (the
//! `gateway.fix_session_state` counter advance + the `gateway.fix_message`
//! store insert) with a **payload-complete** outbox row in the SAME
//! transaction (`insert_outbox_row_with_publisher`): `event_type`, `env_id`,
//! subject, correlation/idempotency ids, and the snapshot the consumer
//! reacts from — no read-back. The shell's outbox relay (boot step 8b)
//! pushes committed rows to Sentin8:Bus `POST /v1/produce`; the gateway
//! never re-implements the relay.
//!
//! Stream family: `gateway` — the Bus stream key is `bus:{env_id}:gateway`;
//! the family slug is validated by `sentin8::bus::outbox::validate_stream_family`
//! (colons are structurally impossible in a family — the event NAMES carry
//! them; the sibling convention covers `me` and `exchange8` families).
//! Event names follow the vertical vocabulary
//! `exchange8:gateway:{resource}:{operation}` (DESIGN.md §4 table).
//!
//! Design: `services/gateway/DESIGN.md` §4 (API surface + event flow), §10.

use serde_json::{json, Value};
use uuid::Uuid;

// ── Event vocabulary (DESIGN.md §4 — colon segments only) ───────────────

/// Stream family for all gateway-emitted events (bare service slug — the
/// Bus `XADD bus:{env}:{family}` key; colons are structurally impossible per
/// `sentin8::bus::outbox::validate_stream_family`).
pub const STREAM_FAMILY: &str = "gateway";
/// `exchange8:gateway:connection:connected` — logon accepted (session
/// Established; credentials verified).
pub const EV_CONNECTION_CONNECTED: &str = "exchange8:gateway:connection:connected";
/// `exchange8:gateway:connection:rejected` — logon rejected (unknown CompID,
/// bad key, or logon-window timeout).
pub const EV_CONNECTION_REJECTED: &str = "exchange8:gateway:connection:rejected";
/// `exchange8:gateway:connection:disconnected` — session teardown (logout,
/// low-seq teardown, TCP/TLS loss, drain, admin stop).
pub const EV_CONNECTION_DISCONNECTED: &str = "exchange8:gateway:connection:disconnected";
/// `exchange8:gateway:order:routed` — order validated and dispatched to its
/// route (ME/OMS/SOR).
pub const EV_ORDER_ROUTED: &str = "exchange8:gateway:order:routed";
/// `exchange8:gateway:order:rejected` — order failed the pipeline before
/// dispatch (shape/validation reject).
pub const EV_ORDER_REJECTED: &str = "exchange8:gateway:order:rejected";
/// `exchange8:me:order:cancel-all` — the cancel-on-disconnect dispatch
/// (business rule 9 — the ME mirror of `CancelAllForConnection`); produced
/// by the gateway's disconnect path, consumed by Exchange8:ME's direct-stream
/// subscriber. The name stays in the ME vocabulary — ME owns the reaction.
pub const EV_ME_CANCEL_ALL: &str = "exchange8:me:order:cancel-all";

/// `fix_message` retention window — the store IS the resend window
/// (DESIGN.md §6 "store purge is the window").
pub const FIX_MESSAGE_RETENTION: &str = "7 days";

/// The identity carried inside every envelope (handler-owned, never derived
/// from DB or headers — event-first: consumers re-key their state without
/// callbacks).
pub struct EventIdentity {
    /// Tenant environment of the event (the connection's `env_id` for
    /// session orders; the cron row's env for the purge fire).
    pub env_id: Uuid,
    /// Acting subject (the session's client CompID for session events; the
    /// cron proxy-back's M2M client id for the purge).
    pub subject_id: String,
    /// Correlation id (generated per session lifetime; for cron fires the
    /// schedule id).
    pub correlation_id: String,
    /// Idempotency key: consumers dedupe on this (the purge fire dedupes on
    /// the schedule id + fired day).
    pub idempotency_key: String,
}

/// Which connection mutation produced the event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionOp {
    /// Logon accepted (the counters row loaded/created; the Logon reply was
    /// stamped).
    Connected,
    /// Logon rejected pre-connection (credential unknown or bad).
    Rejected,
    /// Session teardown (logout, low-seq, loss, drain, admin stop).
    Disconnected,
}

/// Envelope for a connection-lifecycle event: the connection identity +
/// protocol context (`snapshot` carries the CompID, the row identity when
/// resolved, and the reject reason for rejections — the session supervisor
/// and ops dashboards react from the payload alone).
pub fn connection_event(op: ConnectionOp, snapshot: Value, identity: &EventIdentity) -> Value {
    let event_type = match op {
        ConnectionOp::Connected => EV_CONNECTION_CONNECTED,
        ConnectionOp::Rejected => EV_CONNECTION_REJECTED,
        ConnectionOp::Disconnected => EV_CONNECTION_DISCONNECTED,
    };
    json!({
        "event_type": event_type,
        "env_id": identity.env_id,
        "subject_id": identity.subject_id,
        "correlation_id": identity.correlation_id,
        "idempotency_key": identity.idempotency_key,
        "snapshot": snapshot,
    })
}

/// Which order mutation produced the event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderOp {
    /// Validated and dispatched to its route.
    Routed,
    /// Failed the pipeline before dispatch.
    Rejected,
}

/// Envelope for an order-submission event: the routing decision + the FULL
/// normalized order snapshot (the consumer — ME/OMS/SOR's intake side or the
/// clearing mirror — reacts from the payload alone; §6.7 completeness rule).
pub fn order_event(op: OrderOp, snapshot: Value, identity: &EventIdentity) -> Value {
    let event_type = match op {
        OrderOp::Routed => EV_ORDER_ROUTED,
        OrderOp::Rejected => EV_ORDER_REJECTED,
    };
    json!({
        "event_type": event_type,
        "env_id": identity.env_id,
        "subject_id": identity.subject_id,
        "correlation_id": identity.correlation_id,
        "idempotency_key": identity.idempotency_key,
        "snapshot": snapshot,
    })
}

/// Envelope for the cancel-on-disconnect mirror (ME reaction from the
/// connection identity alone).
pub fn me_cancel_all_event(conn_id: Uuid, identity: &EventIdentity) -> Value {
    json!({
        "event_type": EV_ME_CANCEL_ALL,
        "env_id": identity.env_id,
        "subject_id": identity.subject_id,
        "correlation_id": identity.correlation_id,
        "idempotency_key": identity.idempotency_key,
        "snapshot": { "connection_id": conn_id },
    })
}

/// Write the outbox row for an envelope in the CALLER's transaction
/// (same tx as the domain change — outbox-first). The relay (shell boot
/// step 8b) pushes it to Bus post-commit; a failed write aborts the
/// caller's tx via `?` at the call site. `publisher_subject` carries the
/// acting subject so consumers can attribute the event.
///
/// # Errors
/// Propagates the SQL error (the validator's rejection of the constant
/// family text is structurally impossible — covered by the registry test).
// The oneshot test binary includes this module but never drives the runtime
// wiring chain (no DB) — test-binary dead code only.
#[cfg_attr(test, allow(dead_code))]
pub async fn emit_outbox(
    tx: &mut sqlx::PgConnection,
    identity: &EventIdentity,
    envelope: &Value,
) -> Result<Uuid, sqlx::Error> {
    let ev = envelope["event_type"].as_str().unwrap_or_default();
    match sentin8::bus::outbox::insert_outbox_row_with_publisher(
        &mut *tx,
        identity.env_id,
        STREAM_FAMILY,
        ev,
        envelope,
        None,
        Some(&identity.subject_id),
    )
    .await
    {
        Ok(id) => Ok(id),
        Err(sentin8::bus::outbox::OutboxError::Db(e)) => Err(e),
        Err(e) => Err(sqlx::Error::Configuration(Box::new(e))),
    }
}

// ── Audit journal (architecture-principles §6.8) ─────────────────────────

/// Audit `action` words accepted by [`journal_mutation`] (maps one-to-one
/// to `sentin8_audit::AuditAction`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditOp {
    /// Resource modified.
    Update,
    /// Lifecycle executed (retention purge run).
    Execute,
}

/// Build the audit envelope for one mutation and write the
/// `gateway.audit_journal` row on the CALLER's transaction (same tx as the
/// domain change; the shell's pusher — boot step 8c — drains it to
/// Sentin8:Sys `POST /v1/audit` with the `gateway-audit` M2M workload).
/// Reads are NOT journalized (audit-journal pattern: state changes only).
///
/// # Errors
/// Propagates the SQL error of the journal INSERT.
pub async fn journal_mutation(
    tx: &mut sqlx::PgConnection,
    identity: &EventIdentity,
    op: AuditOp,
    resource_type: &str,
    resource_id: &str,
    message: &str,
    before: Option<Value>,
    after: Option<Value>,
) -> Result<(), sqlx::Error> {
    use sentin8::audit::{AuditAction, AuditEvent, AuditSeverity};
    let action = match op {
        AuditOp::Update => AuditAction::Update,
        AuditOp::Execute => AuditAction::Execute,
    };
    let ev = AuditEvent::builder()
        .service("exchange8:gateway")
        .action(action)
        .resource(resource_type, resource_id)
        .actor(&identity.subject_id, "machine")
        .tenant(Uuid::nil(), identity.env_id)
        .severity(AuditSeverity::Info)
        .correlation_id(&identity.correlation_id)
        .message(message);
    let ev = match before {
        Some(b) => ev.before(b),
        None => ev,
    };
    let ev = match after {
        Some(aft) => ev.after(aft),
        None => ev,
    };
    sentin8::audit::journal_insert(&mut *tx, &ev.build()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONNECTION_EVENTS: &[(&str, &str)] = &[
        (EV_CONNECTION_CONNECTED, "connected"),
        (EV_CONNECTION_REJECTED, "rejected"),
        (EV_CONNECTION_DISCONNECTED, "disconnected"),
    ];
    const ORDER_EVENTS: &[(&str, &str)] =
        &[(EV_ORDER_ROUTED, "routed"), (EV_ORDER_REJECTED, "rejected")];

    fn identity() -> EventIdentity {
        EventIdentity {
            env_id: Uuid::nil(),
            subject_id: "NORTHWIND".into(),
            correlation_id: "corr-1".into(),
            idempotency_key: "idem-1".into(),
        }
    }

    #[test]
    fn event_names_follow_the_colon_format() {
        for n in CONNECTION_EVENTS
            .iter()
            .chain(ORDER_EVENTS.iter())
            .map(|(n, _)| *n)
            .chain([EV_ME_CANCEL_ALL])
        {
            // Format contract: `vertical:service:resource:operation` —
            // all-colon segments, no dots. Hyphenated segments are the
            // platform's scope convention.
            let segs: Vec<&str> = n.split(':').collect();
            assert_eq!(segs.len(), 4, "{n}: must have 4 segments");
            assert_eq!(segs[0], "exchange8", "{n}: wrong vertical");
            assert!(n.find('.').is_none(), "{n}: dots are not event format");
            let lower = |s: &str| {
                s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            };
            assert!(segs.iter().all(|s| !s.is_empty() && lower(s)), "{n}");
        }
        // The gateway-owned names all carry the gateway service segment.
        for (n, _) in CONNECTION_EVENTS.iter().chain(ORDER_EVENTS.iter()) {
            assert_eq!(n.split(':').nth(1), Some("gateway"));
        }
        // The ME mirror event stays in the ME vocabulary (ME owns the
        // consumer reaction; the gateway only dispatches the trigger).
        assert_eq!(EV_ME_CANCEL_ALL.split(':').nth(1), Some("me"));
    }

    #[test]
    fn stream_family_is_the_validator_safe_slug() {
        // Colons (event-vocabulary form) are structurally impossible in the
        // stream family — `validate_stream_family` enforces `^[a-zA-Z0-9._-]+$`.
        assert!(sentin8::bus::outbox::validate_stream_family(STREAM_FAMILY).is_ok());
        assert!(sentin8::bus::outbox::validate_stream_family("exchange8:connection").is_err());
    }

    #[test]
    fn envelopes_carry_the_complete_identity_block() {
        let id = identity();
        for envelope in [
            connection_event(
                ConnectionOp::Connected,
                json!({ "connection_id": Uuid::nil(), "client_comp_id": "NORTHWIND" }),
                &id,
            ),
            connection_event(ConnectionOp::Rejected, json!({ "reason": "bad_key" }), &id),
            connection_event(ConnectionOp::Disconnected, json!({}), &id),
            order_event(OrderOp::Routed, json!({ "route": "me" }), &id),
            order_event(OrderOp::Rejected, json!({ "reject": "ZeroQty" }), &id),
            me_cancel_all_event(Uuid::nil(), &id),
        ] {
            assert!(envelope["event_type"].as_str().is_some());
            assert!(envelope["env_id"].is_string() || envelope["env_id"].is_null());
            assert!(envelope["subject_id"].is_string());
            assert!(envelope["correlation_id"].is_string());
            assert!(envelope["idempotency_key"].is_string());
            assert!(envelope["snapshot"].is_object());
        }
        // Routed/rejected map to the declared vocabulary 1:1.
        assert_eq!(
            order_event(OrderOp::Routed, json!({}), &id)["event_type"],
            EV_ORDER_ROUTED
        );
        assert_eq!(
            connection_event(ConnectionOp::Disconnected, json!({}), &id)["event_type"],
            EV_CONNECTION_DISCONNECTED
        );
    }

    #[test]
    fn retention_window_is_the_stored_interval() {
        assert_eq!(FIX_MESSAGE_RETENTION, "7 days");
    }
}
