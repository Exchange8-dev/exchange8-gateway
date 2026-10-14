-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
-- SPDX-License-Identifier: Apache-2.0

-- Ex8:Gateway — client sessions, FIX session state, message retention (D4).
--
-- Design: design/sentin8-exchange8-data-model-technical-design.md §3.2 (GW).
-- No migration code (new platform): `sentin8-cli vertical init` applies this.

CREATE SCHEMA IF NOT EXISTS gateway;

-- FIX/OUCH/WS client sessions (legacy CONNECTION).
CREATE TABLE IF NOT EXISTS gateway.connection (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id              UUID NOT NULL,
    client_comp_id      TEXT NOT NULL UNIQUE,
    status              TEXT NOT NULL DEFAULT 'E' CHECK (status IN ('E','D','H')),
    cancel_on_disconnect BOOLEAN NOT NULL DEFAULT FALSE,
    vendor_id           TEXT,
    book_tokens         TEXT[] NOT NULL DEFAULT '{}',
    price_protection    TEXT NOT NULL DEFAULT 'P'
                        CHECK (price_protection IN ('K','P')),
    risk_bypass         BOOLEAN NOT NULL DEFAULT FALSE,
    gateway_instance    TEXT,
    protocol           TEXT NOT NULL DEFAULT 'FIX'
                        CHECK (protocol IN ('FIX','OUCH','WS','REST')),
    certification_status TEXT NOT NULL DEFAULT 'certified'
                        CHECK (certification_status IN
                        ('certified','provisional','revoked'))
);
CREATE INDEX IF NOT EXISTS idx_exchange8_connection_env ON gateway.connection (env_id);

-- Per-connection in/out sequences + trace toggle (replaces legacy mmap files).
CREATE TABLE IF NOT EXISTS gateway.fix_session_state (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    connection_id   UUID NOT NULL REFERENCES gateway.connection(id),
    in_seq          BIGINT NOT NULL DEFAULT 1,
    out_seq         BIGINT NOT NULL DEFAULT 1,
    trace_enabled   BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (env_id, connection_id)
);

-- Outbound application messages (legacy MESSAGE) — retention-purged (D4).
CREATE TABLE IF NOT EXISTS gateway.fix_message (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    connection_id   UUID NOT NULL REFERENCES gateway.connection(id),
    seq_no          BIGINT NOT NULL,
    msg_type        CHAR(1) NOT NULL,
    msg_body        BYTEA NOT NULL,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (connection_id, seq_no)
);
CREATE INDEX IF NOT EXISTS idx_exchange8_fixmsg_env_ts ON gateway.fix_message (env_id, ts);

-- ---------------------------------------------------------------------------
-- RLS (architecture-principles.md §4.3): enable + force on all tenant tables.
-- Policies use the platform helpers sentin8_context_initialized() and
-- sentin8_current_env_id(); services call set_tenant_context on the same
-- connection as the data query.
-- ---------------------------------------------------------------------------
DO $$
DECLARE tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['gateway.connection', 'gateway.fix_session_state', 'gateway.fix_message'] LOOP
        BEGIN
            EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
            EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);
            EXECUTE format('DROP POLICY IF EXISTS %1$I_select ON %2$s;
CREATE POLICY %1$I_select ON %2$s FOR SELECT USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', split_part(tbl, '.', 2), tbl);
            EXECUTE format('DROP POLICY IF EXISTS %1$I_insert ON %2$s;
CREATE POLICY %1$I_insert ON %2$s FOR INSERT WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', split_part(tbl, '.', 2), tbl);
            EXECUTE format('DROP POLICY IF EXISTS %1$I_update ON %2$s;
CREATE POLICY %1$I_update ON %2$s FOR UPDATE USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', split_part(tbl, '.', 2), tbl);
            EXECUTE format('DROP POLICY IF EXISTS %1$I_delete ON %2$s;
CREATE POLICY %1$I_delete ON %2$s FOR DELETE USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', split_part(tbl, '.', 2), tbl);
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'RLS setup failed for %: %', tbl, SQLERRM;
        END;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- Per-service role grants (schema-per-service: this service owns schema
-- `gateway`; grants live in db `exchange8` only — design doc §1).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'exchange8_gateway_service') THEN
        ALTER ROLE exchange8_gateway_service SET search_path = gateway, public;
        GRANT USAGE ON SCHEMA gateway TO exchange8_gateway_service;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA gateway TO exchange8_gateway_service;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA gateway TO exchange8_gateway_service;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Local outbox (DBX §6.7 — generated from `sentin8_outbox::outbox_table_sql(
-- "gateway")`): rows written in the same DB transaction as the domain change;
-- the shell's relay (boot step §8b) pushes them to Bus `POST /v1/produce`.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS gateway.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gateway_outbox_unrelayed
    ON gateway.outbox (created_at) WHERE relayed = false;
DO $$ BEGIN
    EXECUTE 'ALTER TABLE gateway.outbox ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE gateway.outbox FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS outbox_select ON gateway.outbox';
    EXECUTE 'CREATE POLICY outbox_select ON gateway.outbox FOR SELECT
        USING (sentin8_context_initialized()
               AND env_id = sentin8_current_env_id())';
    EXECUTE 'DROP POLICY IF EXISTS outbox_insert ON gateway.outbox';
    EXECUTE 'CREATE POLICY outbox_insert ON gateway.outbox FOR INSERT
        WITH CHECK (sentin8_context_initialized()
               AND env_id = sentin8_current_env_id())';
    EXECUTE 'DROP POLICY IF EXISTS outbox_update ON gateway.outbox';
    EXECUTE 'CREATE POLICY outbox_update ON gateway.outbox FOR UPDATE
        USING (sentin8_context_initialized()
               AND env_id = sentin8_current_env_id())';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'RLS setup failed for gateway.outbox: %', SQLERRM;
END $$;

CREATE OR REPLACE FUNCTION gateway.gateway_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('gateway_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON gateway.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON gateway.outbox
    FOR EACH ROW
    EXECUTE FUNCTION gateway.gateway_notify_outbox();

-- ---------------------------------------------------------------------------
-- Local audit journal (DBX §6.8 — generated from
-- `sentin8_audit::audit_journal_sql("gateway")`): rows written in the same
-- transaction as the domain change; the shell's pusher (boot step §8c) pushes
-- them to Sys `POST /v1/audit` (`sentin8:sys:audit:write`). A Sys outage
-- never drops audit.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS gateway.audit_journal (
    id              UUID PRIMARY KEY,
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_journal_unpushed
    ON gateway.audit_journal (created_at) WHERE pushed = false;
DO $$ BEGIN
    EXECUTE 'ALTER TABLE gateway.audit_journal ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE gateway.audit_journal FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS audit_journal_dml ON gateway.audit_journal';
    EXECUTE 'CREATE POLICY audit_journal_dml ON gateway.audit_journal
        USING (sentin8_context_initialized()
               AND env_id = sentin8_current_env_id())
        WITH CHECK (sentin8_context_initialized()
               AND env_id = sentin8_current_env_id())';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'RLS setup failed for gateway.audit_journal: %', SQLERRM;
END $$;

-- Outbox + journal role grants (same pattern as the table grants above).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'exchange8_gateway_service') THEN
        GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA gateway TO exchange8_gateway_service;
    END IF;
END $$;
