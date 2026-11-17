import hashlib
import hmac
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row

SCHEMA = """
CREATE TABLE IF NOT EXISTS aegis_users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_salt BYTEA NOT NULL,
    password_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS aegis_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES aegis_users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS aegis_sessions_user_idx ON aegis_sessions(user_id);
CREATE TABLE IF NOT EXISTS aegis_apps (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES aegis_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT,
    token_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    token_last_used_at TIMESTAMPTZ,
    token_revoked BOOLEAN NOT NULL DEFAULT false,
    token_revoked_at TIMESTAMPTZ,
    active_policy JSONB NOT NULL DEFAULT
        '{"approved_vendors":["Acme Supplies","Globex","Initech"],"blocked_vendors":[],"allowed_recipients":["billing@acme.example","accounts@globex.example"],"blocked_recipients":[],"admin_only_records":["admin-keys"],"block_sensitive_egress":true}'::jsonb,
    policy_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS aegis_apps_owner_idx ON aegis_apps(owner_id);
CREATE TABLE IF NOT EXISTS aegis_schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS aegis_security_audit (
    id UUID PRIMARY KEY,
    app_id UUID NOT NULL REFERENCES aegis_apps(id) ON DELETE CASCADE,
    actor_id UUID NOT NULL REFERENCES aegis_users(id),
    actor_label TEXT NOT NULL,
    action TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS aegis_security_audit_app_created_idx
    ON aegis_security_audit(app_id, created_at DESC);
CREATE TABLE IF NOT EXISTS aegis_app_identity_keys (
    app_id UUID NOT NULL REFERENCES aegis_apps(id) ON DELETE CASCADE,
    kid TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_by UUID NOT NULL REFERENCES aegis_users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deactivated_at TIMESTAMPTZ,
    PRIMARY KEY (app_id, kid)
);
CREATE TABLE IF NOT EXISTS aegis_identity_jti (
    app_id UUID NOT NULL REFERENCES aegis_apps(id) ON DELETE CASCADE,
    jti TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, jti)
);
CREATE INDEX IF NOT EXISTS aegis_identity_jti_expiry_idx
    ON aegis_identity_jti(expires_at);
CREATE TABLE IF NOT EXISTS aegis_runs (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES aegis_users(id) ON DELETE CASCADE,
    app_id UUID NOT NULL REFERENCES aegis_apps(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS aegis_runs_app_created_idx
    ON aegis_runs(app_id, created_at DESC);
CREATE TABLE IF NOT EXISTS aegis_events (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES aegis_users(id) ON DELETE CASCADE,
    app_id UUID NOT NULL REFERENCES aegis_apps(id) ON DELETE CASCADE,
    run_id UUID REFERENCES aegis_runs(id) ON DELETE SET NULL,
    tool TEXT NOT NULL,
    role TEXT NOT NULL,
    allowed BOOLEAN NOT NULL,
    reason TEXT NOT NULL,
    arguments JSONB NOT NULL DEFAULT '{}'::jsonb,
    verified_user_id TEXT,
    identity_status TEXT NOT NULL DEFAULT 'valid',
    role_mismatch BOOLEAN NOT NULL DEFAULT false,
    incident_severity TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS aegis_events_app_created_idx
    ON aegis_events(app_id, created_at DESC);
CREATE TABLE IF NOT EXISTS aegis_probe_results (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES aegis_users(id) ON DELETE CASCADE,
    app_id UUID NOT NULL REFERENCES aegis_apps(id) ON DELETE CASCADE,
    run_id UUID NOT NULL REFERENCES aegis_runs(id) ON DELETE CASCADE,
    probe_id TEXT NOT NULL,
    category TEXT NOT NULL,
    passed BOOLEAN NOT NULL,
    detail TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS aegis_probe_run_idx ON aegis_probe_results(run_id);
CREATE TABLE IF NOT EXISTS aegis_patch_proposals (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES aegis_users(id) ON DELETE CASCADE,
    app_id UUID NOT NULL REFERENCES aegis_apps(id) ON DELETE CASCADE,
    incident_id UUID REFERENCES aegis_events(id) ON DELETE SET NULL,
    run_id UUID REFERENCES aegis_runs(id) ON DELETE SET NULL,
    finding TEXT NOT NULL,
    patch JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS aegis_proposals_app_created_idx
    ON aegis_patch_proposals(app_id, created_at DESC);
ALTER TABLE aegis_apps ADD COLUMN IF NOT EXISTS active_policy JSONB NOT NULL DEFAULT
    '{"approved_vendors":["Acme Supplies","Globex","Initech"],"blocked_vendors":[],"allowed_recipients":["billing@acme.example","accounts@globex.example"],"blocked_recipients":[],"admin_only_records":["admin-keys"],"block_sensitive_egress":true}'::jsonb;
ALTER TABLE aegis_apps ADD COLUMN IF NOT EXISTS policy_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE aegis_apps ADD COLUMN IF NOT EXISTS token_prefix TEXT;
ALTER TABLE aegis_apps ADD COLUMN IF NOT EXISTS token_created_at TIMESTAMPTZ;
ALTER TABLE aegis_apps ADD COLUMN IF NOT EXISTS token_last_used_at TIMESTAMPTZ;
ALTER TABLE aegis_apps ADD COLUMN IF NOT EXISTS token_revoked BOOLEAN;
ALTER TABLE aegis_apps ADD COLUMN IF NOT EXISTS token_revoked_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS aegis_apps_token_prefix_uidx
    ON aegis_apps(token_prefix) WHERE token_prefix IS NOT NULL;
ALTER TABLE aegis_events ADD COLUMN IF NOT EXISTS verified_user_id TEXT;
ALTER TABLE aegis_events ADD COLUMN IF NOT EXISTS identity_status TEXT NOT NULL DEFAULT 'valid';
ALTER TABLE aegis_events ADD COLUMN IF NOT EXISTS role_mismatch BOOLEAN NOT NULL DEFAULT false;
UPDATE aegis_apps
SET active_policy = active_policy || '{"admin_only_records":["admin-keys"]}'::jsonb
WHERE NOT (active_policy ? 'admin_only_records');
UPDATE aegis_apps
SET active_policy = active_policy || '{"blocked_vendors":[]}'::jsonb
WHERE NOT (active_policy ? 'blocked_vendors');
"""


def database_url() -> str:
    value = os.environ.get("DATABASE_URL")
    if not value:
        raise RuntimeError(
            "DATABASE_URL is not configured; set it to the PostgreSQL URL "
            "for the Aegis database"
        )
    return value


def hash_app_token(token: str) -> str:
    pepper = os.environ.get("AEGIS_TOKEN_PEPPER", "")
    pepper_bytes = pepper.encode("utf-8")
    if len(pepper_bytes) < 32:
        raise RuntimeError(
            "AEGIS_TOKEN_PEPPER must be configured with at least 32 bytes"
        )
    return hmac.new(
        pepper_bytes,
        token.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


@contextmanager
def connection() -> Iterator[psycopg.Connection[dict[str, Any]]]:
    with psycopg.connect(database_url(), row_factory=dict_row) as conn:
        yield conn


def initialize() -> None:
    with connection() as conn:
        for statement in SCHEMA.split(";"):
            if statement.strip():
                conn.execute(statement)
        migrated = conn.execute(
            "SELECT 1 FROM aegis_schema_migrations WHERE version = '2026-identity-token-lifecycle'"
        ).fetchone()
        if migrated is None:
            conn.execute(
                """
                UPDATE aegis_apps
                SET token_revoked = true,
                    token_created_at = COALESCE(token_created_at, created_at)
                """
            )
            conn.execute(
                """
                INSERT INTO aegis_schema_migrations (version)
                VALUES ('2026-identity-token-lifecycle')
                """
            )
        conn.execute(
            "UPDATE aegis_apps SET token_revoked = false WHERE token_revoked IS NULL"
        )
        conn.execute(
            "UPDATE aegis_apps SET token_created_at = created_at WHERE token_created_at IS NULL"
        )
        conn.execute(
            "ALTER TABLE aegis_apps ALTER COLUMN token_revoked SET DEFAULT false"
        )
        conn.execute(
            "ALTER TABLE aegis_apps ALTER COLUMN token_revoked SET NOT NULL"
        )


def create_user(
    email: str,
    password_salt: bytes,
    password_hash: bytes,
) -> dict[str, Any]:
    user_id = uuid4()
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO aegis_users (id, email, password_salt, password_hash)
            VALUES (%s, %s, %s, %s)
            RETURNING id, email, created_at
            """,
            (user_id, email, password_salt, password_hash),
        ).fetchone()
    if row is None:
        raise RuntimeError("Database did not return the created user")
    return row


def get_user_by_email(email: str) -> dict[str, Any] | None:
    with connection() as conn:
        return conn.execute(
            """
            SELECT id, email, password_salt, password_hash
            FROM aegis_users WHERE email = %s
            """,
            (email,),
        ).fetchone()


def create_session(token_hash: str, user_id: str) -> None:
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO aegis_sessions (token_hash, user_id, expires_at)
            VALUES (%s, %s, now() + interval '12 hours')
            """,
            (token_hash, user_id),
        )


def get_session_user(token_hash: str) -> dict[str, Any] | None:
    with connection() as conn:
        return conn.execute(
            """
            SELECT u.id, u.email
            FROM aegis_sessions s
            JOIN aegis_users u ON u.id = s.user_id
            WHERE s.token_hash = %s AND s.expires_at > now()
            """,
            (token_hash,),
        ).fetchone()


def delete_session(token_hash: str) -> None:
    with connection() as conn:
        conn.execute("DELETE FROM aegis_sessions WHERE token_hash = %s", (token_hash,))


def create_app(
    owner_id: str,
    name: str,
    token_hash: str,
    token_prefix: str,
) -> dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO aegis_apps
                (id, owner_id, name, token_hash, token_prefix, token_created_at)
            VALUES (%s, %s, %s, %s, %s, now())
            RETURNING id, name, token_prefix, token_created_at,
                      token_last_used_at, token_revoked, created_at
            """,
            (uuid4(), owner_id, name, token_hash, token_prefix),
        ).fetchone()
    if row is None:
        raise RuntimeError("Database did not return the created application")
    return row


def list_apps(owner_id: str) -> list[dict[str, Any]]:
    with connection() as conn:
        return list(
            conn.execute(
                """
                SELECT id, name, token_prefix, token_created_at,
                       token_last_used_at, token_revoked, created_at
                FROM aegis_apps WHERE owner_id = %s
                ORDER BY created_at, name
                """,
                (owner_id,),
            ).fetchall()
        )


def authenticate_app(token_prefix: str, token_hash: str) -> dict[str, Any] | None:
    with connection() as conn:
        app = conn.execute(
            """
            SELECT a.id, a.name, a.owner_id, a.token_hash,
                   a.active_policy, a.policy_version
            FROM aegis_apps a
            WHERE a.token_prefix = %s AND a.token_revoked = false
            """,
            (token_prefix,),
        ).fetchone()
        stored_hash = app["token_hash"] if app is not None else "0" * 64
        token_matches = hmac.compare_digest(stored_hash, token_hash)
        if app is None or not token_matches:
            return None
        conn.execute(
            "UPDATE aegis_apps SET token_last_used_at = now() WHERE id = %s",
            (app["id"],),
        )
        app.pop("token_hash", None)
        return app


def rotate_app_token(
    owner_id: str,
    app_id: str,
    token_hash: str,
    token_prefix: str,
) -> dict[str, Any] | None:
    with connection() as conn:
        return conn.execute(
            """
            UPDATE aegis_apps
            SET token_hash = %s, token_prefix = %s, token_created_at = now(),
                token_last_used_at = NULL, token_revoked = false,
                token_revoked_at = NULL
            WHERE id = %s AND owner_id = %s
            RETURNING id, name, token_prefix, token_created_at,
                      token_last_used_at, token_revoked
            """,
            (token_hash, token_prefix, app_id, owner_id),
        ).fetchone()


def revoke_app_token(owner_id: str, app_id: str) -> dict[str, Any] | None:
    with connection() as conn:
        return conn.execute(
            """
            UPDATE aegis_apps
            SET token_revoked = true, token_revoked_at = now()
            WHERE id = %s AND owner_id = %s AND token_revoked = false
            RETURNING id, name, token_prefix, token_created_at,
                      token_last_used_at, token_revoked, token_revoked_at
            """,
            (app_id, owner_id),
        ).fetchone()


def get_owned_app(owner_id: str, app_id: str) -> dict[str, Any] | None:
    with connection() as conn:
        return conn.execute(
            """
            SELECT id, name, owner_id, active_policy, policy_version,
                   token_prefix, token_created_at, token_last_used_at,
                   token_revoked, token_revoked_at
            FROM aegis_apps
            WHERE id = %s AND owner_id = %s
            """,
            (app_id, owner_id),
        ).fetchone()


def record_security_audit(
    *,
    app_id: str,
    actor_id: str,
    actor_label: str,
    action: str,
    details: dict[str, Any],
) -> dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO aegis_security_audit
                (id, app_id, actor_id, actor_label, action, details)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb)
            RETURNING id, app_id, actor_id, actor_label, action, details, created_at
            """,
            (
                uuid4(),
                app_id,
                actor_id,
                actor_label,
                action,
                json.dumps(details),
            ),
        ).fetchone()
    if row is None:
        raise RuntimeError("Database did not return the security audit event")
    return row


def append_event(
    *,
    owner_id: str,
    app_id: str,
    tool: str,
    role: str,
    allowed: bool,
    reason: str,
    arguments: dict[str, Any],
    verified_user_id: str | None = None,
    identity_status: str = "valid",
    role_mismatch: bool = False,
    run_id: str | None = None,
) -> dict[str, Any]:
    event_id = uuid4()
    severity = None if allowed else (
        "high" if tool in {"pay_invoice", "send_email", "post_chat"} else "medium"
    )
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO aegis_events
                (id, owner_id, app_id, run_id, tool, role, allowed,
                 reason, arguments, verified_user_id, identity_status,
                 role_mismatch, incident_severity)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s)
            RETURNING id, app_id, run_id, tool, role, allowed, reason,
                      arguments, verified_user_id, identity_status, role_mismatch,
                      incident_severity, created_at
            """,
            (
                event_id,
                owner_id,
                app_id,
                run_id,
                tool,
                role,
                allowed,
                reason,
                json.dumps(arguments),
                verified_user_id,
                identity_status,
                role_mismatch,
                severity,
            ),
        ).fetchone()
    if row is None:
        raise RuntimeError("Database did not return the created event")
    return row


def list_events(owner_id: str, app_id: str, limit: int = 100) -> list[dict[str, Any]]:
    with connection() as conn:
        return list(
            conn.execute(
                """
                SELECT id, app_id, run_id, tool, role, allowed, reason,
                       arguments, verified_user_id, identity_status, role_mismatch,
                       incident_severity, created_at
                FROM aegis_events
                WHERE owner_id = %s AND app_id = %s
                ORDER BY created_at DESC LIMIT %s
                """,
                (owner_id, app_id, limit),
            ).fetchall()
        )


def list_incidents(
    owner_id: str, app_id: str, limit: int = 100
) -> list[dict[str, Any]]:
    with connection() as conn:
        return list(
            conn.execute(
                """
                SELECT id, app_id, run_id, tool, role, reason,
                       verified_user_id, identity_status, role_mismatch,
                       incident_severity AS severity, created_at,
                       'contained' AS status,
                       'tool call denied before execution' AS action
                FROM aegis_events
                WHERE owner_id = %s AND app_id = %s AND allowed = false
                ORDER BY created_at DESC LIMIT %s
                """,
                (owner_id, app_id, limit),
            ).fetchall()
        )


def add_identity_key(
    app_id: str,
    kid: str,
    public_key: str,
    created_by: str,
) -> dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO aegis_app_identity_keys (app_id, kid, public_key, created_by)
            VALUES (%s, %s, %s, %s)
            RETURNING app_id, kid, public_key, created_at, deactivated_at
            """,
            (app_id, kid, public_key, created_by),
        ).fetchone()
    if row is None:
        raise RuntimeError("Database did not return the identity key")
    return row


def list_identity_keys(app_id: str) -> list[dict[str, Any]]:
    with connection() as conn:
        return list(
            conn.execute(
                """
                SELECT kid, public_key, created_at, deactivated_at
                FROM aegis_app_identity_keys
                WHERE app_id = %s
                ORDER BY created_at, kid
                """,
                (app_id,),
            ).fetchall()
        )


def active_identity_keys(app_id: str) -> dict[str, str]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT kid, public_key
            FROM aegis_app_identity_keys
            WHERE app_id = %s AND deactivated_at IS NULL
            """,
            (app_id,),
        ).fetchall()
    return {row["kid"]: row["public_key"] for row in rows}


def deactivate_identity_key(app_id: str, kid: str) -> bool:
    with connection() as conn:
        result = conn.execute(
            """
            UPDATE aegis_app_identity_keys
            SET deactivated_at = now()
            WHERE app_id = %s AND kid = %s AND deactivated_at IS NULL
            """,
            (app_id, kid),
        )
        return result.rowcount == 1


def consume_identity_jti(app_id: str, jti: str, expires_at: int) -> bool:
    with connection() as conn:
        conn.execute(
            "DELETE FROM aegis_identity_jti WHERE expires_at < now() - interval '30 seconds'"
        )
        result = conn.execute(
            """
            INSERT INTO aegis_identity_jti (app_id, jti, expires_at)
            VALUES (%s, %s, to_timestamp(%s))
            ON CONFLICT (app_id, jti) DO NOTHING
            """,
            (app_id, jti, expires_at),
        )
        return result.rowcount == 1


def create_run(owner_id: str, app_id: str, kind: str) -> str:
    run_id = uuid4()
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO aegis_runs (id, owner_id, app_id, kind, status)
            VALUES (%s, %s, %s, %s, 'running')
            """,
            (run_id, owner_id, app_id, kind),
        )
    return str(run_id)


def complete_run(
    run_id: str, status: str, summary: dict[str, Any]
) -> None:
    with connection() as conn:
        cursor = conn.execute(
            """
            UPDATE aegis_runs
            SET status = %s, summary = %s::jsonb, completed_at = now()
            WHERE id = %s
            """,
            (status, json.dumps(summary), run_id),
        )
        if cursor.rowcount != 1:
            raise KeyError("Run not found")


def append_probe_result(
    *,
    owner_id: str,
    app_id: str,
    run_id: str,
    probe_id: str,
    category: str,
    passed: bool,
    detail: str,
) -> None:
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO aegis_probe_results
                (id, owner_id, app_id, run_id, probe_id, category, passed, detail)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                uuid4(),
                owner_id,
                app_id,
                run_id,
                probe_id,
                category,
                passed,
                detail,
            ),
        )


def list_runs(owner_id: str, app_id: str, limit: int = 50) -> list[dict[str, Any]]:
    with connection() as conn:
        return list(
            conn.execute(
                """
                SELECT id, kind, status, summary, created_at, completed_at
                FROM aegis_runs
                WHERE owner_id = %s AND app_id = %s
                ORDER BY created_at DESC LIMIT %s
                """,
                (owner_id, app_id, limit),
            ).fetchall()
        )


def list_proposals(owner_id: str, app_id: str) -> list[dict[str, Any]]:
    with connection() as conn:
        return list(
            conn.execute(
                """
                SELECT id, incident_id, run_id, finding, patch, status,
                       created_at, decided_at
                FROM aegis_patch_proposals
                WHERE owner_id = %s AND app_id = %s
                ORDER BY created_at DESC LIMIT 50
                """,
                (owner_id, app_id),
            ).fetchall()
        )


def create_patch_proposal(
    *,
    owner_id: str,
    app_id: str,
    incident_id: str | None,
    run_id: str | None,
    finding: str,
    patch: dict[str, Any],
) -> dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO aegis_patch_proposals
                (id, owner_id, app_id, incident_id, run_id, finding, patch, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, 'pending')
            RETURNING id, app_id, incident_id, run_id, finding, patch,
                      status, created_at, decided_at
            """,
            (
                uuid4(),
                owner_id,
                app_id,
                incident_id,
                run_id,
                finding,
                json.dumps(patch),
            ),
        ).fetchone()
    if row is None:
        raise RuntimeError("Database did not return the patch proposal")
    return row


def get_owned_proposal(
    owner_id: str, app_id: str, proposal_id: str
) -> dict[str, Any] | None:
    with connection() as conn:
        return conn.execute(
            """
            SELECT id, owner_id, app_id, incident_id, run_id, finding, patch, status
            FROM aegis_patch_proposals
            WHERE id = %s AND app_id = %s AND owner_id = %s
            """,
            (proposal_id, app_id, owner_id),
        ).fetchone()


def decide_proposal(
    proposal_id: str,
    owner_id: str,
    app_id: str,
    status: str,
) -> None:
    with connection() as conn:
        cursor = conn.execute(
            """
            UPDATE aegis_patch_proposals
            SET status = %s, decided_at = now()
            WHERE id = %s AND owner_id = %s AND app_id = %s AND status = 'pending'
            """,
            (status, proposal_id, owner_id, app_id),
        )
        if cursor.rowcount != 1:
            raise KeyError("Pending proposal not found")


def approve_proposal(
    proposal_id: str, owner_id: str, app_id: str
) -> int:
    with connection() as conn:
        proposal = conn.execute(
            """
            SELECT patch, status FROM aegis_patch_proposals
            WHERE id = %s AND owner_id = %s AND app_id = %s
            FOR UPDATE
            """,
            (proposal_id, owner_id, app_id),
        ).fetchone()
        if proposal is None or proposal["status"] != "pending":
            raise KeyError("Pending proposal not found")
        patch = proposal["patch"]
        if not patch.get("red_verification", {}).get("summary", {}).get("passed"):
            raise ValueError("Patch has not passed Red and benign verification")
        app_update = conn.execute(
            """
            UPDATE aegis_apps
            SET active_policy = %s::jsonb, policy_version = policy_version + 1
            WHERE id = %s AND owner_id = %s
            RETURNING policy_version
            """,
            (json.dumps(patch["candidate_policy"]), app_id, owner_id),
        ).fetchone()
        if app_update is None:
            raise KeyError("Application not found")
        conn.execute(
            """
            UPDATE aegis_patch_proposals
            SET status = 'approved', decided_at = now()
            WHERE id = %s
            """,
            (proposal_id,),
        )
        return app_update["policy_version"]
