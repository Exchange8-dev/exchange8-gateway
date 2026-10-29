// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Exchange8:GATEWAY (generated; hand-tune freely).
//!
//! Output via `--print-registration` (see the platform
//! `sentin8-service-self-registration-design.md`).

use utoipa::OpenApi;

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, ErrorCode, M2mGrant, PgRole, PolicySetDecl, Registration,
    RelationDecl, ScheduleDecl, SqlMigration,
};

/// The Shield text of the declared scope-mirror set - public so the
/// policy wiring tests assert against the REAL seed.
///
/// Coverage contract (policy wiring tests): EVERY action the handlers
/// evaluate has a permit - the connection read/write vocabulary, the
/// cron proxy-back's purge action (the cron workload's declared
/// `sentin8:cron:write` is the admitted scope), and the platform-admin trio
/// rides every surface.
pub const SCOPE_MIRROR_POLICIES: &str = "permit(principal, action == Action::\"exchange8:connection:read\", resource) when { principal.scopes.contains(\"exchange8:connection:read\") };
permit(principal, action == Action::\"exchange8:connection:read\", resource) when { principal.scopes.contains(\"exchange8:connection:all\") };
permit(principal, action == Action::\"exchange8:connection:read\", resource) when { principal.scopes.contains(\"exchange8:connection:write\") };
permit(principal, action == Action::\"exchange8:connection:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"exchange8:connection:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"exchange8:connection:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"exchange8:connection:write\", resource) when { principal.scopes.contains(\"exchange8:connection:write\") };
permit(principal, action == Action::\"exchange8:connection:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"exchange8:connection:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"exchange8:connection:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"exchange8:gateway:fix-message:purge\", resource) when { principal.scopes.contains(\"sentin8:cron:write\") };
permit(principal, action == Action::\"exchange8:gateway:fix-message:purge\", resource) when { principal.scopes.contains(\"exchange8:gateway:fix-message:purge\") };
permit(principal, action == Action::\"exchange8:gateway:fix-message:purge\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"exchange8:gateway:fix-message:purge\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"exchange8:gateway:fix-message:purge\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };";

/// Default declarative policy set (Sentin8:Policy design §3.2/§3.4,
/// seeded by `vertical enroll` as `origin='platform'`, `mode='enforced'`):
/// action-granular scope permits over the LIVE effective scope set - the
/// exact mirror of the gates this service's handlers evaluate in step 5
/// (policy design §4.3; see DESIGN.md §4). The enforced step-5 evaluation
/// is the only request-time gate; shadow is the emergency one-UPDATE
/// rollback lever only.
const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for exchange8:gateway over the LIVE effective scope set. Enforced - step 5 is the only gate.",
    // Shield text lives in SCOPE_MIRROR_POLICIES (single source).
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples (design §3.1c) - none declared by this
/// service today; env admins author their own graph via the relations
/// admin API.
const RELATIONS: &[RelationDecl] = &[];

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "exchange8:connection:read,exchange8:connection:write",
    role: "exchange8_gateway_service",
    bypass_rls: false,
    // Grants live in the exchange8 vertical database only (principles §6.6
    // database-per-vertical, schema-per-service).
    database: "exchange8",
    // This service owns all its reads - no cross-schema grants.
    cross_schema_grants: &[],
}];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed {
        role: "exchange8:admin",
        scope: "exchange8:connection:read",
    },
    AdminScope::Typed {
        role: "exchange8:admin",
        scope: "exchange8:connection:write",
    },
    // The retention purge surface (DESIGN.md §6): the env admin role maps it
    // so an env operator can trigger the purge run manually too.
    AdminScope::Typed {
        role: "exchange8:admin",
        scope: "exchange8:gateway:fix-message:purge",
    },
    // Policy-admin surface (policy design §3.6; principles §6.0b per-service scope).
    AdminScope::Typed {
        role: "exchange8:gateway:admin",
        scope: "exchange8:gateway:policy:read",
    },
    AdminScope::Typed {
        role: "exchange8:gateway:admin",
        scope: "exchange8:gateway:policy:write",
    },
];

const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode {
        enum_name: "Exchange8LogonRejected",
        error_code: "exchange8_logon_rejected",
        status_code: 401,
    },
    ErrorCode {
        enum_name: "Exchange8SeqTooLow",
        error_code: "exchange8_seq_too_low",
        status_code: 400,
    },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "sessions",
        label: "Sessions",
        ui_endpoint: "/v1/admin/ui/sessions",
        data_endpoint: "/v1/admin/sessions",
        icon: "0xe8cc",
    },
    AdminUiPage {
        route: "messages",
        label: "Messages",
        ui_endpoint: "/v1/admin/ui/messages",
        data_endpoint: "/v1/admin/messages",
        icon: "0xe6e1",
    },
];

/// Workload scope grants (self-registration design §3.11). One entry per
/// workload this service presents a certificate for; `vertical enroll` upserts the
/// rows so the fail-closed registry map admits the registration. Scopes use the
/// full vocabulary form:
/// - `exchange8:gateway` / `gateway` - the service's own client (both
///   spellings granted; runtime call sites use the bare short name, the
///   map looks up the exact workload): bus produce/consume + the
///   shared certificate identity.
/// - `exchange8:gateway-policy` / `gateway-policy` - Shield hot-reload
///   consumer + stat emitter pair.
/// - `gateway-audit` - shell audit-journal pusher workload (§6.8; boot 8c).
/// - `gateway-cron` - the retention purge schedule self-registration (the
///   refdata/secrets precedents): the boot registers the recurring
///   `fix-message-purge` schedule with Sentin8:Cron; Cron's ticker
///   proxy-back authenticates the dedicated `gateway-cron` workload.
/// - `exchange8-gateway-tls` - database-free HostContextResolver resolve workload
/// (`GET /v1/resolve/hostname`, scope
///   `sentin8:sys:instances:read`).
const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "exchange8:gateway",
        scopes: &[
            "exchange8:connection:read",
            "exchange8:connection:write",
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
        ],
    },
    M2mGrant {
        workload: "gateway",
        scopes: &[
            "exchange8:connection:read",
            "exchange8:connection:write",
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
        ],
    },
    M2mGrant {
        workload: "exchange8:gateway-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    M2mGrant {
        workload: "gateway-policy",
        scopes: &["sentin8:stat:measure"],
    },
    M2mGrant {
        workload: "gateway-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    // Retention purge schedule self-registration (DESIGN.md §6): the boot
    // registers the recurring `fix-message-purge` schedule with Sentin8:Cron;
    // Cron's ticker proxy-back authenticates the dedicated `gateway-cron`
    // workload (refdata transition-worker precedent).
    M2mGrant {
        workload: "gateway-cron",
        scopes: &["sentin8:cron:write"],
    },
    M2mGrant {
        workload: "exchange8-gateway-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

fn empty_openapi() -> serde_json::Value {
    serde_json::to_value(crate::openapi::GatewayOpenApi::openapi())
        .unwrap_or(serde_json::Value::Null)
}

pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "exchange8:gateway",
        subdomain: "exchange8-gateway",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: ERROR_CODES,
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Gateway",
            icon: "0xe1b1",
            service_flag: "exchange8-gateway",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        pg_roles: PG_ROLES,
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: empty_openapi,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        // Retention purge (SDD §2.4): the recurring `fix-message-purge`
        // schedule - daily 05:30 UTC (before market open). Provisioned at
        // enroll; the fire proxy-calls this service's
        // `/v1/internal/schedules/run` (constants in
        // `runtime_wiring::retention` keep the contract honest).
        schedules: &[ScheduleDecl {
            schedule_type: "fix-message-purge",
            cron_expression: "30 5 * * *",
            timezone: "UTC",
            target_config: r#"{"internalPath": "/v1/internal/schedules/run", "scheduleType": "fix-message-purge"}"#,
            max_retries: 3,
        }],
    };
    sentin8::registration::print_registration(section, &reg, empty_openapi)
}
