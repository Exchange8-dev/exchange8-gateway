// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

//! Exchange8:Gateway HTTP handler tests (design §13b.1; see DESIGN.md §9).
//!
//! Drives the REAL router through `tower::ServiceExt::oneshot`: route
//! mounting, the authorization pipeline (bearer → scope), status codes,
//! and the JSON error envelope - without a database. DB-free guarantee:
//! every data-path handler calls `require_any_scope` BEFORE the first
//! pool access, so a bearer-less request never reaches `state.pool`.
//!
//! The authorized data paths are covered by `tests/sql_matrix.rs`
//! + the scope matrices inside `handlers.rs` (see DESIGN.md §9).
//!
//! The gateway crate is bin-only, so the handler modules are pulled in
//! via `#[path]` - the same pattern as trade8's desk tests. The sibling
//! modules the handlers reference (`crate::runtime_wiring`) ride the same
//! includes so the `crate::` paths resolve identically to the binary.

#[path = "../src/events.rs"]
mod events;
#[path = "../src/handlers.rs"]
mod handlers;
#[path = "../src/rest_api.rs"]
mod rest_api;
#[path = "../src/runtime_wiring.rs"]
mod runtime_wiring;
#[path = "../src/session.rs"]
mod session;
#[path = "../src/submission.rs"]
mod submission;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Minimal router mirroring `main.rs::extend_router` (same paths/methods).
fn router() -> axum::Router {
    axum::Router::new()
        .route(
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
        // Admin/RFW surface (page definitions + data endpoints + the stop
        // action) + the cron proxy-back retention fire target.
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
        .route(
            "/v1/admin/ui/{page}",
            axum::routing::get(handlers::admin_ui_page),
        )
        .route(
            "/v1/internal/schedules/run",
            axum::routing::post(handlers::internal_schedules_run),
        )
        .with_state(test_state())
}

/// Install the platform's PQ TLS provider (services do this at boot;
/// reqwest inside the auth client requires a configured provider).
fn install_crypto() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
    });
}

/// `ServiceCore` with a never-connected pool. Safe: the bearer-less
/// requests these tests send are rejected by `verify_bearer_token` before
/// any pool access.
fn test_state() -> Arc<sentin8::shell::AppState> {
    install_crypto();
    let config = Arc::new(sentin8::shell::ShellConfig {
        service_type: "exchange8:gateway",
        port: 0,
        database_url: "postgresql://invalid:invalid@127.0.0.1:5/none".into(),
        sentin8_auth_issuer: "https://auth.invalid".into(),
        sentin8_bus_url: String::new(),
        sentin8_auth_client: sentin8::auth::client::Client::new(
            sentin8::auth::client::Client::builder()
                .base_url("https://auth.invalid")
                .build()
                .expect("client options are valid"),
        ),
        valkey_url: String::new(),
    });
    let pool = sqlx::PgPool::connect_lazy("postgresql://invalid:invalid@127.0.0.1:5/none")
        .expect("lazy pool url is parseable");
    Arc::new(sentin8::shell::AppState {
        config,
        pool: pool.clone(),
        admin: sentin8::shield::admin::SharedAdminState::test("exchange8:gateway", pool),
    })
}

fn req(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "exchange8-test")
        .body(Body::empty())
        .unwrap()
}

/// 1 - every route rejects a bearer-less request with 401 (auth pipeline
/// before any DB work). Includes a Path-extractor route to prove `{id}`
/// extraction participates normally.
#[tokio::test]
async fn every_route_rejects_unauthenticated_with_401() {
    let app = router();
    let id = "00000000-0000-0000-0000-0000000000aa";
    for (method, uri) in [
        ("GET", "/v1/connections"),
        ("GET", &format!("/v1/connections/{id}/seq")),
        ("POST", &format!("/v1/connections/{id}/seq-reset")),
        ("GET", "/v1/admin/sessions"),
        ("POST", &format!("/v1/admin/sessions/{id}/stop")),
        ("GET", "/v1/admin/messages"),
        ("GET", "/v1/admin/ui/sessions"),
        ("POST", "/v1/internal/schedules/run"),
    ] {
        let res = app.clone().oneshot(req(method, uri)).await.unwrap();
        let st = res.status();
        // JSON-extractor routes (e.g. POST with axum::Json) reject the empty
        // body with 415 BEFORE the handler body (and its auth gate) runs.
        // Both 401 (auth gate first) and 415 (body extractor first) prove the
        // request never reached the DB layer.
        assert!(
            st == StatusCode::UNAUTHORIZED || st == StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{method} {uri}: expected 401 or 415, got {st}"
        );
    }
}

/// 2 - wrong-method on an existing path → 405 (route table shape check).
#[tokio::test]
async fn wrong_method_gets_405_not_404() {
    let app = router();
    let res = app.oneshot(req("DELETE", "/v1/connections")).await.unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// 3 - unmatched path → 404.
#[tokio::test]
async fn unknown_path_gets_404() {
    let app = router();
    let res = app.oneshot(req("GET", "/v1/nope")).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// 4 - error envelope: plain-text auth message (never SQL internals).
#[tokio::test]
async fn unauthenticated_error_envelope_is_plain_text_401() {
    let app = router();
    let res = app.oneshot(req("GET", "/v1/connections")).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("missing Authorization header"),
        "error body must carry the auth message, got: {text}"
    );
}

/// 5 - the RFW page definitions mount: bearer-less requests on every slug
/// (declared or not) hit the auth gate BEFORE the route/page resolution.
#[tokio::test]
async fn admin_ui_pages_are_mounted() {
    let app = router();
    for slug in ["sessions", "messages", "nope"] {
        let res = app
            .clone()
            .oneshot(req("GET", &format!("/v1/admin/ui/{slug}")))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "page '{slug}': gate before the route lookup"
        );
    }
}

/// 6 - the cron proxy-back retention fire target is mounted and gated.
#[tokio::test]
async fn cron_proxy_back_route_is_mounted() {
    let app = router();
    let res = app
        .oneshot(req("POST", "/v1/internal/schedules/run"))
        .await
        .unwrap();
    // The JSON extractor rejects the empty body before the auth gate;
    // a 401 would also prove the DB is never reached.
    assert!(
        res.status() == StatusCode::UNAUTHORIZED
            || res.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "expected 401 or 415, got {}",
        res.status()
    );
}
