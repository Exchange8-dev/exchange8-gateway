// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for Exchange8:Gateway.
//!
//! utoipa annotations on the service's handlers + the shared Shield
//! policy-admin surface (`sentin8::shell::policy_*` wrappers); the
//! shell-owned `/v1/health` mount is described through a spec wrapper
//! (`sentin8/design/sentin8-openapi-coverage-design.md` §2).

use utoipa::OpenApi;

pub mod w {

    /// Spec wrapper for the shell-owned `/v1/health` mount.
    #[utoipa::path(
        get,
        path = "/v1/health",
        responses(
            (status = 200, description = "Service is healthy", body = serde_json::Value),
        ),
        security(),
        tag = "gateway",
    )]
    pub async fn gateway_health() {}
    /// Spec wrapper for the alias route (same handler as the public path).
    #[utoipa::path(
        get,
        path = "/v1/admin/connections",
        responses(
            (status = 200, description = "OK", body = serde_json::Value),
            (status = 403, description = "Forbidden"),
        ),
        security(),
        tag = "exchange8-admin",
    )]
    pub async fn admin_list_connections() {}

    /// Spec wrapper for the alias route (same handler as the public path).
    #[utoipa::path(
        get,
        path = "/v1/admin/sessions",
        responses(
            (status = 200, description = "OK", body = serde_json::Value),
            (status = 403, description = "Forbidden"),
        ),
        security(),
        tag = "exchange8-admin",
    )]
    pub async fn admin_list_sessions() {}

    /// Spec wrapper for the alias route (same handler as the public path).
    #[utoipa::path(
        post,
        path = "/v1/admin/sessions/{id}/stop",
        responses(
            (status = 200, description = "OK", body = serde_json::Value),
            (status = 403, description = "Forbidden"),
        ),
        security(),
        tag = "exchange8-admin",
    )]
    pub async fn admin_stop_session_post() {}

    /// Spec wrapper for the alias route (same handler as the public path).
    #[utoipa::path(
        get,
        path = "/ws",
        responses(
            (status = 200, description = "OK", body = serde_json::Value),
            (status = 403, description = "Forbidden"),
        ),
        security(),
        tag = "gateway",
    )]
    pub async fn ws_upgrade() {}
}

/// OpenAPI spec for the gateway API.
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::openapi::w::admin_list_connections,
        crate::openapi::w::admin_list_sessions,
        crate::openapi::w::admin_stop_session_post,
        crate::openapi::w::ws_upgrade,
crate::handlers::list_connections,
crate::handlers::get_seq_state,
crate::handlers::seq_reset,
crate::handlers::stop_session,
crate::handlers::list_fix_messages,
crate::handlers::admin_ui_page,
crate::handlers::internal_schedules_run,
crate::openapi::w::gateway_health,
        sentin8::shell::policy_list_sets,
        sentin8::shell::policy_get_set,
        sentin8::shell::policy_put_set,
        sentin8::shell::policy_delete_set,
        sentin8::shell::policy_test_set,
        sentin8::shell::policy_mode_enforce,
        sentin8::shell::policy_mode_shadow,
        sentin8::shell::policy_mode_disable,
        sentin8::shell::policy_create_set,
        sentin8::shell::policy_save_set,
        sentin8::shell::policy_flip_set,
        sentin8::shell::policy_list_decisions,
        sentin8::shell::policy_delete_relation_path,
        sentin8::shell::policy_delete_attribute_path,
        sentin8::shell::policy_list_relations,
        sentin8::shell::policy_put_relation,
        sentin8::shell::policy_delete_relation,
        sentin8::shell::policy_check_relation,
        sentin8::shell::policy_list_attributes,
        sentin8::shell::policy_put_attribute,
        sentin8::shell::policy_delete_attribute,
    ),
    components(schemas()),
    security(),
    tags(
        (name = "gateway", description = "Exchange8:Gateway"),
        (name = "exchange8-admin", description = "Exchange8 admin surface (RFW)"),
        (name = "policy", description = "Shield policy administration (shared surface)"),
    ),
)]
pub struct GatewayOpenApi;
