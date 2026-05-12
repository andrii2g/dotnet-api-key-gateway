CREATE TABLE IF NOT EXISTS api_keys (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    app VARCHAR(3) NOT NULL,
    env VARCHAR(10) NOT NULL,
    public_key CHAR(16) NOT NULL,
    hash VARCHAR(255) NOT NULL,
    scopes JSON NOT NULL,
    expires_at DATETIME(6) NULL,
    revoked_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NULL,
    last_used_at DATETIME(6) NULL,
    name VARCHAR(100) NULL,
    created_by VARCHAR(100) NULL,
    last_used_ip VARCHAR(64) NULL,
    last_used_user_agent VARCHAR(512) NULL,
    UNIQUE KEY ux_api_keys_public_key (public_key)
);
