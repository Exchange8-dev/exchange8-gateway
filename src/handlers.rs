// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

//! Exchange8:Gateway data handlers - FIX session/connection management API.
//!
//! Every handler follows the platform authorization pipeline (§5): verify
//! bearer → scope check → RLS context (same connection) → explicit
//! `WHERE env_id` (defense-in-depth) → query.
//!
//! Design: `design/sentin8-exchange8-gateway-technical-design.md` §4.1
//! + data-model doc §3.2 (GW-owned `gateway.connection`).

use utoipa::ToSchema;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::Acquire;
use uuid::Uuid;

use sentin8::shell::{err_db, AppState};

/// Scope constants for every handler in this module - single source of truth
/// for both the call sites and the authorization matrix tests (design
/// §13b.1; see DESIGN.md §4).
pub mod scopes {
    /// `GET /v1/connections` + `GET /v1/connections/{id}/seq`.
    pub const CONNECTIONS_READ: &str = "exchange8:connection:read";
    /// `POST /v1/connections/{id}/seq-reset` - admin sequence reset.
    pub const CONNECTIONS_WRITE: &str = "exchange8:connection:write";
    /// The cron proxy-back purge action (WORKER contract, see
    /// `runtime_wiring::retention`); the mirror admits the cron workload's
    /// `sentin8:cron:write` (the refdata transition-action convention).
    pub const FIX_MESSAGE_PURGE: &str = "exchange8:gateway:fix-message:purge";
}

#[derive(Debug, Deserialize)]
pub struct ListConnectionsQuery {
    /// Filter by status E/D/H.
    pub status: Option<String>,
    pub limit: Option<i64>,
}

/// The correlation id from the platform middleware (`X-Sentin8-Correlation-
/// Id` is propagated by the shell's correlation middleware; a missing header
/// - direct CLI/dev calls - generates one so the envelope stays complete).
fn correlation_from(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-sentin8-correlation-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

/// JSON serialization failure mapping (a FromRow→Value snapshot is
/// infallible by construction - the mapping exists so `?` stays uniform).
fn err_db_json(e: serde_json::Error) -> (StatusCode, String) {
    err_db(e)
}

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct ConnectionResponse {
    pub id: Uuid,
    pub env_id: Uuid,
    pub client_comp_id: String,
    pub status: String,
    pub cancel_on_disconnect: bool,
    pub vendor_id: Option<String>,
    pub protocol: String,
    pub certification_status: String,
    pub price_protection: String,
    pub risk_bypass: bool,
}
#[utoipa::path(
    get,
    path = "/v1/connections",
    responses(
        (status = 200, description = "FIX connections", body = Vec<ConnectionResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "gateway",
)]

/// `GET /v1/connections` - list client sessions (RLS-scoped).
pub async fn list_connections(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(q): Query<ListConnectionsQuery>,
) -> Result<Json<Vec<ConnectionResponse>>, (StatusCode, String)> {
    let a = sentin8::shell::verify_token(&state.config, &headers).await?;
    sentin8::shell::policy::require(
        &state.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("exchange8:connection:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    let mut ctx = conn.begin().await.map_err(err_db)?;
    sentin8::shell::set_tenant_context(&mut ctx, a.env_id()).await;
    let limit = q.limit.unwrap_or(100).min(500);
    let rows = sqlx::query_as::<_, ConnectionResponse>(
        r#"SELECT id, env_id, client_comp_id, status, cancel_on_disconnect,
                  vendor_id, protocol, certification_status, price_protection,
                  risk_bypass
             FROM gateway.connection
            WHERE env_id = $1
              AND ($2::text IS NULL OR status = $2)
            ORDER BY client_comp_id LIMIT $3"#,
    )
    .bind(a.env_id())
    .bind(q.status.as_deref())
    .bind(limit)
    .fetch_all(&mut *ctx)
    .await
    .map_err(err_db)?;
    ctx.commit().await.map_err(err_db)?;
    Ok(Json(rows))
}

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct SeqStateResponse {
    pub id: Uuid,
    pub env_id: Uuid,
    pub connection_id: Uuid,
    pub in_seq: i64,
    pub out_seq: i64,
    pub trace_enabled: bool,
}
#[utoipa::path(
    get,
    path = "/v1/connections/{id}/seq",
    responses(
        (status = 200, description = "Sequence state", body = SeqStateResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "gateway",
)]

/// `GET /v1/connections/{id}/seq` - persisted FIX sequence counters.
pub async fn get_seq_state(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(conn_id): Path<Uuid>,
) -> Result<Json<SeqStateResponse>, (StatusCode, String)> {
    let a = sentin8::shell::verify_token(&state.config, &headers).await?;
    sentin8::shell::policy::require(
        &state.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("exchange8:connection:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    let mut ctx = conn.begin().await.map_err(err_db)?;
    sentin8::shell::set_tenant_context(&mut ctx, a.env_id()).await;
    let row = sqlx::query_as::<_, SeqStateResponse>(
        r#"SELECT id, env_id, connection_id, in_seq, out_seq, trace_enabled
             FROM gateway.fix_session_state
            WHERE env_id = $1 AND connection_id = $2"#,
    )
    .bind(a.env_id())
    .bind(conn_id)
    .fetch_optional(&mut *ctx)
    .await
    .map_err(err_db)?;
    ctx.commit().await.map_err(err_db)?;
    row.map(Json)
        .ok_or((StatusCode::NOT_FOUND, "connection not found".into()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SeqResetRequest {
    /// Reset both counters to 1.
    pub to: Option<i64>,
}
#[utoipa::path(
    post,
    path = "/v1/connections/{id}/seq-reset",
    responses(
        (status = 200, description = "Sequence reset", body = SeqStateResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "gateway",
)]

/// `POST /v1/connections/{id}/seq-reset` - admin sequence reset
/// (the platform spec seq reset parity; design §6 admin ops).
pub async fn seq_reset(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(conn_id): Path<Uuid>,
    axum::extract::Json(req): axum::extract::Json<SeqResetRequest>,
) -> Result<Json<SeqStateResponse>, (StatusCode, String)> {
    let a = sentin8::shell::verify_token(&state.config, &headers).await?;
    sentin8::shell::policy::require(
        &state.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new(scopes::CONNECTIONS_WRITE),
    )
    .await?;
    let to = req.to.unwrap_or(1);
    if to < 1 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "sequence must start at 1".into(),
        ));
    }
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    let mut ctx = conn.begin().await.map_err(err_db)?;
    sentin8::shell::set_tenant_context(&mut ctx, a.env_id()).await;
    let row = sqlx::query_as::<_, SeqStateResponse>(
        r#"UPDATE gateway.fix_session_state
              SET in_seq = $3, out_seq = $3
            WHERE env_id = $1 AND connection_id = $2
          RETURNING id, env_id, connection_id, in_seq, out_seq, trace_enabled"#,
    )
    .bind(a.env_id())
    .bind(conn_id)
    .bind(to)
    .fetch_optional(&mut *ctx)
    .await
    .map_err(err_db)?;
    // Durability pair on the SAME tx: the audit journal row for the admin
    // mutation (DESIGN.md §5 audit journaling; the shell pusher - boot 8c -
    // drains it to Sys).
    if let Some(after_row) = &row {
        use crate::events::{journal_mutation, AuditOp, EventIdentity};
        let identity = EventIdentity {
            env_id: a.env_id(),
            subject_id: a.claims.sub.clone(),
            correlation_id: correlation_from(&headers),
            idempotency_key: format!("seq-reset:{}", after_row.id),
        };
        let snapshot = serde_json::to_value(after_row).map_err(err_db_json)?;
        journal_mutation(
            &mut ctx,
            &identity,
            AuditOp::Update,
            "fix_session_state",
            &conn_id.to_string(),
            &format!("admin sequence reset to {to}"),
            None,
            Some(snapshot),
        )
        .await
        .map_err(err_db)?;
    }
    ctx.commit().await.map_err(err_db)?;
    row.map(Json)
        .ok_or((StatusCode::NOT_FOUND, "connection not found".into()))
}

// ---------------------------------------------------------------------------
// Admin/RFW surface (DESIGN.md §4 admin surface; registration declares the
// pages `sessions` / `messages`). `GET /v1/admin/ui/{page}` serves the RFW
// page-definition JSON (Sentin8:Dash renders it - services never ship UI
// code); the `/v1/admin/*` data endpoints alias the same RLS-scoped
// handlers. Admin session stop rides the runtime session registry
// (DESIGN.md §4.5 admin logout).
// ---------------------------------------------------------------------------

/// The RFW page definitions for this service's `admin_ui` pages - same
/// definition shape the Dash renderer consumes (`admin_ui` module
/// machinery to follow the refdata pattern; this module holds the pure
/// definition data for gateway's own pages).
pub mod admin_pages {
    /// The `sessions` page (registration `ADMIN_UI_PAGES[0]`): the FIX
    /// session/connection table + the admin session-stop action.
    pub fn sessions() -> serde_json::Value {
        serde_json::json!({
            "slug": "sessions",
            "title": "Sessions",
            "icon": "0xe8cc",
            "scope": "exchange8:connection:read",
            "sections": [
                {
                    "type": "table",
                    "heading": "FIX/OUCH sessions",
                    "resource": "sessions",
                    "columns": [
                        {"key": "client_comp_id", "label": "CompID"},
                        {"key": "protocol", "label": "Protocol"},
                        {"key": "status", "label": "Status"},
                        {"key": "certification_status", "label": "Certified"}
                    ]
                },
                {
                    "type": "action",
                    "heading": "Stop session",
                    "resource": "sessions",
                    "label": "Stop",
                    "fields": [{"key": "id", "label": "Connection ID"}]
                }
            ]
        })
    }

    /// The `messages` page (`ADMIN_UI_PAGES[1]`): the resend-window message
    /// store table (retention-purged; DESIGN.md §6).
    pub fn messages() -> serde_json::Value {
        serde_json::json!({
            "slug": "messages",
            "title": "Messages",
            "icon": "0xe6e1",
            "scope": "exchange8:connection:read",
            "sections": [
                {
                    "type": "table",
                    "heading": "FIX message store (resend window)",
                    "resource": "messages",
                    "columns": [
                        {"key": "client_comp_id", "label": "CompID"},
                        {"key": "seq_no", "label": "Seq"},
                        {"key": "msg_type", "label": "Type"},
                        {"key": "ts", "label": "Timestamp"}
                    ]
                }
            ]
        })
    }

    /// Resolve a page slug to its RFW definition.
    pub fn page(slug: &str) -> Option<serde_json::Value> {
        match slug {
            "sessions" => Some(sessions()),
            "messages" => Some(messages()),
            _ => None,
        }
    }
}
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    responses(
        (status = 200, description = "RFW page definition", body = AdminRfwPage),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "exchange8-admin",
)]

/// `GET /v1/admin/ui/{page}` - the RFW page definition (Dash renders it;
/// gated by the page's declared admin scope).
pub async fn admin_ui_page(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(page): Path<String>,
) -> Result<axum::Json<AdminRfwPage>, (StatusCode, String)> {
    let a = sentin8::shell::verify_token(&state.config, &headers).await?;
    sentin8::shell::policy::require(
        &state.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new(scopes::CONNECTIONS_READ),
    )
    .await?;
    admin_pages::page(&page)
        .map(AdminRfwPage)
        .map(axum::Json)
        .ok_or((StatusCode::NOT_FOUND, format!("no admin ui page '{page}'")))
}
#[utoipa::path(
    post,
    path = "/v1/admin/sessions",
    responses(
        (status = 200, description = "Session stopped", body = SessionStopAck),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "exchange8-admin",
)]

/// `POST /v1/admin/sessions/{id}/stop` - admin session stop (design §4.5
/// `sessions` page action; the runtime registry delivers the logout).
pub async fn stop_session(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(conn_id): Path<Uuid>,
) -> Result<axum::Json<SessionStopAck>, (StatusCode, String)> {
    let a = sentin8::shell::verify_token(&state.config, &headers).await?;
    sentin8::shell::policy::require(
        &state.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new(scopes::CONNECTIONS_WRITE),
    )
    .await?;
    // RLS-scoped existence probe first - an invalid id must 404, not 200.
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    let mut ctx = conn.begin().await.map_err(err_db)?;
    sentin8::shell::set_tenant_context(&mut ctx, a.env_id()).await;
    sqlx::query("SELECT 1 FROM gateway.connection WHERE env_id = $1 AND id = $2")
        .bind(a.env_id())
        .bind(conn_id)
        .fetch_optional(&mut *ctx)
        .await
        .map_err(err_db)?
        .ok_or((StatusCode::NOT_FOUND, "connection not found".into()))?;
    // Durability pair on the SAME tx: the audit journal row for the admin
    // mutation (DESIGN.md §5 audit journaling).
    {
        use crate::events::{journal_mutation, AuditOp, EventIdentity};
        let identity = EventIdentity {
            env_id: a.env_id(),
            subject_id: a.claims.sub.clone(),
            correlation_id: correlation_from(&headers),
            idempotency_key: format!("session-stop:{conn_id}"),
        };
        journal_mutation(
            &mut ctx,
            &identity,
            AuditOp::Update,
            "connection",
            &conn_id.to_string(),
            "admin session stop requested",
            None,
            Some(serde_json::json!({ "status": "stopped" })),
        )
        .await
        .map_err(err_db)?;
    }
    ctx.commit().await.map_err(err_db)?;
    // Deliver the stop signal; a session not currently connected is a
    // no-op stop (the state table already carries the persisted counters).
    crate::runtime_wiring::stop_session(conn_id).await;
    Ok(axum::Json(SessionStopAck {
        id: conn_id,
        stopped: true,
    }))
}
#[utoipa::path(
    get,
    path = "/v1/admin/messages",
    responses(
        (status = 200, description = "FIX journal rows", body = Vec<FixMessageResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "exchange8-admin",
)]

/// `GET /v1/admin/messages` - the resend-window store rows (the `messages`
/// page data endpoint; retention-purged per DESIGN.md §6).
pub async fn list_fix_messages(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(q): Query<ListConnectionsQuery>,
) -> Result<Json<Vec<FixMessageResponse>>, (StatusCode, String)> {
    let a = sentin8::shell::verify_token(&state.config, &headers).await?;
    sentin8::shell::policy::require(
        &state.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new(scopes::CONNECTIONS_READ),
    )
    .await?;
    let limit = q.limit.unwrap_or(100).min(500);
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    let mut ctx = conn.begin().await.map_err(err_db)?;
    sentin8::shell::set_tenant_context(&mut ctx, a.env_id()).await;
    let rows = sqlx::query_as::<_, FixMessageResponse>(
        r#"SELECT m.id, m.env_id, m.connection_id, m.seq_no, m.msg_type, m.ts
             FROM gateway.fix_message m
            WHERE m.env_id = $1
            ORDER BY m.ts DESC LIMIT $2"#,
    )
    .bind(a.env_id())
    .bind(limit)
    .fetch_all(&mut *ctx)
    .await
    .map_err(err_db)?;
    ctx.commit().await.map_err(err_db)?;
    Ok(Json(rows))
}

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct FixMessageResponse {
    pub id: uuid::Uuid,
    pub env_id: uuid::Uuid,
    pub connection_id: uuid::Uuid,
    pub seq_no: i64,
    pub msg_type: String,
    pub ts: chrono::DateTime<chrono::Utc>,
}

/// `POST /v1/internal/schedules/run` - the Sentin8:Cron proxy-back fire
/// target for the `fix-message-purge` retention schedule (DESIGN.md §6; the
/// refdata/secrets precedents). The caller is the `gateway-cron` M2M
/// workload - the bearer is verified like any principal (steps 1-4) and the
/// step-5 gate evaluates the dedicated purge action, which the seeded
/// mirror admits via the cron workload's `sentin8:cron:write`. The DELETE
/// runs on this service's OWN schema (owner-side maintenance - the
/// retention window spans all envs, so the purge resolves envs from the
/// owner-side helper; the schema is service-private).
#[derive(Debug, Deserialize, ToSchema)]
pub struct ScheduleRunRequest {
    pub schedule_id: Option<Uuid>,
    pub schedule_type: String,
    /// The env the cron row carries (informational for the purge - the
    /// window spans every env; the response echoes it).
    pub env_id: Uuid,
    pub correlation_id: Option<String>,
    /// The cron ticker's job idempotency key - carried through to the audit
    /// trail; the purge itself dedupes on the window predicate.
    #[allow(dead_code)]
    pub idempotency_key: Option<String>,
}
/// Session-stop ack (OAPEC-9 typed body).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct SessionStopAck {
    /// The stopped session id.
    pub id: uuid::Uuid,
    /// Always `true`.
    pub stopped: bool,
}

/// Cron proxy-back ack (`{schedule_type, env_id, purged}` - gateway's own
/// key set, distinct from refdata's `{advanced}`).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct ScheduleRunResponse {
    /// The schedule_type that ran.
    pub schedule_type: String,
    /// The env served.
    pub env_id: uuid::Uuid,
    /// Dropped FIX frames purged.
    pub purged: u64,
}

/// The RFW page-definition document (transparent renderer-contract JSON).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct AdminRfwPage(
    /// The RFW page-definition document.
    pub serde_json::Value,
);

#[utoipa::path(
    post,
    path = "/v1/internal/schedules/run",
    request_body = ScheduleRunRequest,
    responses(
        (status = 200, description = "Schedule advanced", body = ScheduleRunResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "gateway-internal",
)]

pub async fn internal_schedules_run(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<ScheduleRunRequest>,
) -> Result<axum::Json<ScheduleRunResponse>, (StatusCode, String)> {
    let a = sentin8::shell::verify_token(&state.config, &headers).await?;
    sentin8::shell::policy::require(
        &state.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new(scopes::FIX_MESSAGE_PURGE),
    )
    .await
    .map(|_| ())?;
    if body.schedule_type != crate::runtime_wiring::retention::CRON_SCHEDULE_TYPE {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("unknown schedule_type {}", body.schedule_type),
        ));
    }
    let purged = crate::runtime_wiring::retention::purge(&state)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Audit the purge run (Execute) - one row per fire; the correlation is
    // the cron row's (schedule id when the ticker omits it).
    {
        let mut conn = state.pool.acquire().await.map_err(err_db)?;
        let mut ctx = conn.begin().await.map_err(err_db)?;
        sentin8::shell::set_tenant_context(&mut ctx, body.env_id).await;
        use crate::events::{journal_mutation, AuditOp, EventIdentity};
        let correlation = body
            .correlation_id
            .clone()
            .unwrap_or_else(|| body.schedule_id.map(|s| s.to_string()).unwrap_or_default());
        let identity = EventIdentity {
            env_id: body.env_id,
            subject_id: a.claims.sub.clone(),
            correlation_id: correlation,
            idempotency_key: body
                .idempotency_key
                .clone()
                .unwrap_or_else(|| body.schedule_id.map(|s| s.to_string()).unwrap_or_default()),
        };
        journal_mutation(
            &mut ctx,
            &identity,
            AuditOp::Execute,
            "fix_message",
            &body.schedule_id.map(|s| s.to_string()).unwrap_or_default(),
            &format!("retention purge executed, {purged} rows deleted"),
            None,
            Some(serde_json::json!({ "purged": purged })),
        )
        .await
        .map_err(err_db)?;
        ctx.commit().await.map_err(err_db)?;
    }
    Ok(axum::Json(ScheduleRunResponse {
        schedule_type: body.schedule_type,
        env_id: body.env_id,
        purged,
    }))
}

// ---------------------------------------------------------------------------
// Authorization matrix tests (design §13b.1; see DESIGN.md §9). DB-free: the
// decision the handlers delegate to (`AuthContext::require_any_scope`) is
// exercised against the SAME constants the handlers require.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod scope_matrix {
    use super::scopes;
    use sentin8::shell::{AuthContext, VerifiedClaims};

    const HANDLER_SCOPES: &[(&str, &[&str])] = &[
        ("list_connections", &[scopes::CONNECTIONS_READ]),
        ("get_seq_state", &[scopes::CONNECTIONS_READ]),
        ("seq_reset", &[scopes::CONNECTIONS_WRITE]),
        ("admin_ui_page", &[scopes::CONNECTIONS_READ]),
        ("stop_session", &[scopes::CONNECTIONS_WRITE]),
        ("list_fix_messages", &[scopes::CONNECTIONS_READ]),
        ("internal_schedules_run", &[scopes::FIX_MESSAGE_PURGE]),
    ];

    const SIBLING_SCOPES: &[&str] = &[
        scopes::CONNECTIONS_READ,
        scopes::CONNECTIONS_WRITE,
        scopes::FIX_MESSAGE_PURGE,
    ];

    fn ctx(scope: &str) -> AuthContext {
        AuthContext {
            claims: VerifiedClaims {
                sub: "matrix-test".into(),
                iss: "https://auth.test".into(),
                aud: "exchange8".into(),
                jti: "matrix-jti".into(),
                iat: 0,
                exp: i64::MAX,
                token_tp: "access".into(),
                scope: scope.into(),
                env_id: Some("00000000-0000-0000-0000-000000000002".into()),
                email: None,
                act: None,
                vertical: None,
                service_type: None,
            },
            // Bearer-path context: no certificate workload on the test
            // identity (CERTFREE-4V - the field exists for the cert path).
            workload: None,
        }
    }

    #[test]
    fn every_handler_denies_without_and_with_wrong_scope() {
        for (handler, required) in HANDLER_SCOPES {
            let err = ctx("")
                .require_any_scope(required)
                .expect_err("no scope must deny");
            assert_eq!(err.0.as_u16(), 403, "{handler}: expected FORBIDDEN");

            let err = ctx("bank8:ledger:read")
                .require_any_scope(required)
                .expect_err("foreign scope must deny");
            assert_eq!(err.0.as_u16(), 403, "{handler}: foreign must be FORBIDDEN");

            for sibling in SIBLING_SCOPES {
                if required.contains(sibling) {
                    continue;
                }
                let err = ctx(sibling)
                    .require_any_scope(required)
                    .expect_err("sibling scope must deny");
                assert_eq!(
                    err.0.as_u16(),
                    403,
                    "{handler}: sibling {sibling} must be FORBIDDEN"
                );
            }
        }
    }

    #[test]
    fn every_handler_allows_each_required_scope_and_platform_admin() {
        for (handler, required) in HANDLER_SCOPES {
            for scope in *required {
                assert!(
                    ctx(scope).require_any_scope(required).is_ok(),
                    "{handler}: exact scope {scope} must allow"
                );
            }
            let all = required.join(" ");
            assert!(ctx(&all).require_any_scope(required).is_ok(), "{handler}");
            assert!(
                ctx("sentin8:sys:admin").require_any_scope(required).is_ok(),
                "{handler}"
            );
        }
    }

    #[test]
    fn grants_are_prefix_permissive_and_denials_are_exact() {
        assert!(ctx("exchange8:connection:read:all")
            .require_any_scope(&[scopes::CONNECTIONS_READ])
            .is_ok());
        assert!(ctx("exchange8:connection:readx")
            .require_any_scope(&[scopes::CONNECTIONS_READ])
            .is_err());
    }

    #[test]
    fn scope_constants_follow_the_naming_convention() {
        // Registered contract: 3-4 segments (see clearing scope_matrix note).
        let mut all: Vec<&str> = Vec::new();
        for (handler, required) in HANDLER_SCOPES {
            for scope in *required {
                all.push(scope);
                let segs: Vec<_> = scope.split(':').collect();
                assert!(
                    (3..=4).contains(&segs.len()),
                    "{handler}: {scope} must have 3-4 segments"
                );
                assert_eq!(segs[0], "exchange8", "{handler}: {scope} wrong vertical");
                assert!(
                    segs.iter().all(|s| !s.is_empty()
                        && s.chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')),
                    "{handler}: {scope} segments must be lowercase alnum/hyphen"
                );
            }
        }
        // Every declared constant must be wired into HANDLER_SCOPES. Shared
        // constants across handlers are legitimate - dedup first.
        all.sort_unstable();
        all.dedup();
        let mut declared = vec![
            scopes::CONNECTIONS_READ,
            scopes::CONNECTIONS_WRITE,
            scopes::FIX_MESSAGE_PURGE,
        ];
        declared.sort_unstable();
        assert_eq!(all, declared, "scopes module and HANDLER_SCOPES diverged");
    }
} // (removed dead type; scope matrix extended with the admin/RFW handlers)
