CREATE TABLE api_keys (
    id BIGSERIAL PRIMARY KEY,
    app VARCHAR(3) NOT NULL,
    env VARCHAR(10) NOT NULL,
    public_key CHAR(16) NOT NULL,
    hash VARCHAR(128) NOT NULL,
    scopes JSONB NOT NULL,
    expires_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NULL,
    last_used_at TIMESTAMPTZ NULL,
    name VARCHAR(100) NULL,
    created_by VARCHAR(100) NULL,
    last_used_ip VARCHAR(45) NULL,
    last_used_user_agent VARCHAR(255) NULL,
    CONSTRAINT ux_api_keys_public_key UNIQUE (public_key),
    CONSTRAINT chk_api_keys_app CHECK (app ~ '^[a-z0-9]{1,3}$'),
    CONSTRAINT chk_api_keys_env CHECK (env ~ '^[a-z0-9_-]{1,10}$'),
    CONSTRAINT chk_api_keys_scopes_array CHECK (jsonb_typeof(scopes) = 'array')
);

CREATE INDEX ix_api_keys_app_env ON api_keys (app, env);
CREATE INDEX ix_api_keys_revoked_expires ON api_keys (revoked_at, expires_at);
