// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

//! Exchange8:GATEWAY service binary — FIX 4.2/OUCH/WS order entry + session management.
//!
//! Design: `design/sentin8-exchange8-gateway-technical-design.md` (see the
//! service doc for the exact file). Core logic in the sibling modules;
//! this shell wires the tokio HTTP/TLS surface via the platform
//! `sentin8-shell` crate (registration, DB pool, health). The dedicated
//! FIX/OUCH TLS listeners, the session-supervisor registry, and the
//! retention executor are spawned by `runtime_wiring::spawn_tasks` from
//! the state closure (design §2 runtime architecture); the shell's own
//! relay (boot 8b) + audit pusher (8c) push the outbox/journal rows this
//! service writes.

#![allow(dead_code)]

use std::sync::Arc;

// Global allocator — mimalloc for every exchange8 service binary
// (master design §11.1). Workers (bus consumers, session
// supervisors, purge jobs) are in-process tokio tasks, so the
// binary-level allocator covers them all.
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod events;
mod exec_report;
mod handlers;
mod ouch;
mod registration;
mod rest_api;
mod runtime_wiring;
mod session;
mod submission;

fn extend_router(
    app: axum::Router<std::sync::Arc<sentin8::shell::AppState>>,
    _state: std::sync::Arc<sentin8::shell::AppState>,
) -> axum::Router<std::sync::Arc<sentin8::shell::AppState>> {
    // ── Sentin8:Policy admin API (shared implementation;
    // the shell AppState already implements HasPolicyAdmin).
    sentin8::shell::mount_policy_admin(
        // FIX/OUCH listeners are dedicated TLS acceptor tasks (design §4.1);
        // the HTTP router exposes connection management (list/seq
        // state/reset/admin session stop, RLS-scoped), the admin/RFW data +
        // page-definition endpoints, the WS upgrade tier, and health.
        app.route(
            "/v1/connections",
            axum::routing::get(handlers::list_connections),
        )
        .route(
            "/v1/connections/{id}/seq",
            axum::routing::get(handlers::get_seq_state),
        )
        .route(
            "/v1/connections/{id}/seq-reset",
            axum::routing::post(handlers::seq_reset),
        )
        // WS order-entry upgrade (the /ws bidirectional tier; design §4).
        .route("/ws", axum::routing::get(runtime_wiring::ws_upgrade))
        // ── Admin/RFW surface (registration admin_ui pages `sessions` +
        // `messages`; DESIGN.md §4 admin surface). Data endpoints alias the
        // same RLS-scoped handlers.
        .route(
            "/v1/admin/connections",
            axum::routing::get(handlers::list_connections),
        )
        .route(
            "/v1/admin/sessions",
            axum::routing::get(handlers::list_connections).post(handlers::stop_session),
        )
        .route(
            "/v1/admin/sessions/{id}/stop",
            axum::routing::post(handlers::stop_session),
        )
        .route(
            "/v1/admin/messages",
            axum::routing::get(handlers::list_fix_messages),
        )
        // RFW page definitions (registration admin_ui: `sessions`,
        // `messages`).
        .route(
            "/v1/admin/ui/{page}",
            axum::routing::get(handlers::admin_ui_page),
        )
        // ── Sentin8:Cron proxy-back: the retention fire target (design §6;
        // Sentin8:Cron presents its own `gateway-cron` M2M token — the
        // step-5 mirror admits the cron scope on the purge action).
        .route(
            "/v1/internal/schedules/run",
            axum::routing::post(handlers::internal_schedules_run),
        ),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("exchange8:gateway", "EXCHANGE8_GATEWAY")
            .with_registration(registration::print)
            // The state closure spawns the protocol acceptors + retention
            // schedule + session registry (runtime architecture §2; shell
            // boot step 8) and keeps the shell `ServiceCore` as the state —
            // handlers extract `State<Arc<AppState>>` unchanged.
            .with_state(|core| async move {
                // The tasks need their own handle to config+pool; clone the
                // cheap Arc fields into a second ServiceCore for the workers
                // (state identity: handlers keep THIS core untouched).
                let workers = sentin8::shell::ServiceCore {
                    config: core.config.clone(),
                    pool: core.pool.clone(),
                    admin: sentin8::shield::admin::SharedAdminState {
                        service: core.admin.service.clone(),
                        pool: core.pool.clone(),
                        policy: core.admin.policy.clone(),
                        auth_client: core.admin.auth_client.clone(),
                    },
                };
                runtime_wiring::spawn_tasks(Arc::new(workers));
                Ok(Arc::new(core))
            })
            .with_router(extend_router),
    )
    .await
}
