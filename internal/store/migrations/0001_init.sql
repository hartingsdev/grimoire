-- Grundschema. users.id ist ein interner Surrogatschlüssel: alle Fremdschlüssel
-- zeigen darauf, damit beim Löschen eines Nutzers die sub geleert werden kann,
-- ohne Historie oder Fremdschlüssel zu zerstören (Grabstein-Zeile).
CREATE TABLE users (
    id             TEXT PRIMARY KEY,
    sub            TEXT UNIQUE,               -- NULL nach Löschung
    email          TEXT,
    display_name   TEXT,
    cached_role    TEXT NOT NULL DEFAULT '',  -- Cache aus dem IdP, NICHT autoritativ
    cached_role_at INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL,
    last_login_at  INTEGER NOT NULL DEFAULT 0,
    deleted_at     INTEGER
);

CREATE TABLE prompts (
    id         TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility IN ('shared','private')),
    owner_id   TEXT NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL REFERENCES users(id),
    deleted_at INTEGER
);
CREATE INDEX prompts_visibility_owner ON prompts(visibility, owner_id);
CREATE INDEX prompts_deleted          ON prompts(deleted_at);
CREATE INDEX prompts_updated          ON prompts(updated_at DESC);

CREATE TABLE tags (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE
);
CREATE TABLE prompt_tags (
    prompt_id TEXT NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
    tag_id    INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (prompt_id, tag_id)
);
CREATE INDEX prompt_tags_tag ON prompt_tags(tag_id);

-- Append-only: jede Fassung vor einer Änderung wird hier abgelegt.
CREATE TABLE prompt_revisions (
    id         INTEGER PRIMARY KEY,
    prompt_id  TEXT NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
    revision   INTEGER NOT NULL,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    visibility TEXT NOT NULL,
    tags_json  TEXT NOT NULL DEFAULT '[]',
    kind       TEXT NOT NULL CHECK (kind IN ('create','update','delete','restore')),
    changed_at INTEGER NOT NULL,
    changed_by TEXT NOT NULL REFERENCES users(id),
    UNIQUE (prompt_id, revision)
);

CREATE TABLE api_keys (
    id             TEXT PRIMARY KEY,          -- öffentliche Key-ID, steht im Klartext im Key
    key_hash       BLOB NOT NULL,             -- SHA-256 des Geheimnisses
    name           TEXT NOT NULL,
    role           TEXT NOT NULL CHECK (role IN ('viewer','editor')),
    owner_id       TEXT REFERENCES users(id), -- NULL vorgesehen für spätere Service-Keys
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    last_used_at   INTEGER NOT NULL DEFAULT 0,
    revoked_at     INTEGER,
    revoked_reason TEXT
);
CREATE INDEX api_keys_owner ON api_keys(owner_id);

CREATE TABLE sessions (
    id               TEXT PRIMARY KEY,        -- 32 Byte Zufall, opak
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role             TEXT NOT NULL,
    csrf_token       TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    last_seen_at     INTEGER NOT NULL,
    revalidate_after INTEGER NOT NULL,
    access_token_enc BLOB,                    -- AES-GCM, Schlüssel aus DATA_ENCRYPTION_KEY
    refresh_token_enc BLOB
);
CREATE INDEX sessions_user    ON sessions(user_id);
CREATE INDEX sessions_expires ON sessions(expires_at);

CREATE TABLE oauth_states (
    state         TEXT PRIMARY KEY,
    nonce         TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    redirect_to   TEXT NOT NULL DEFAULT '/',
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    at          INTEGER NOT NULL,
    actor_id    TEXT REFERENCES users(id),
    actor_kind  TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at ON audit_log(at DESC);

-- Denormalisierte Suchquelle. Die Trigger halten den FTS5-Index synchron,
-- damit kein Codepfad ihn vergessen kann.
CREATE TABLE prompt_search (
    prompt_id TEXT PRIMARY KEY REFERENCES prompts(id) ON DELETE CASCADE,
    title     TEXT NOT NULL,
    body      TEXT NOT NULL,
    tags      TEXT NOT NULL DEFAULT ''
);

CREATE VIRTUAL TABLE prompts_fts USING fts5(
    title, body, tags,
    content='prompt_search', content_rowid='rowid',
    tokenize="unicode61 remove_diacritics 2"
);

CREATE TRIGGER prompt_search_ai AFTER INSERT ON prompt_search BEGIN
    INSERT INTO prompts_fts(rowid, title, body, tags)
    VALUES (new.rowid, new.title, new.body, new.tags);
END;
CREATE TRIGGER prompt_search_ad AFTER DELETE ON prompt_search BEGIN
    INSERT INTO prompts_fts(prompts_fts, rowid, title, body, tags)
    VALUES ('delete', old.rowid, old.title, old.body, old.tags);
END;
CREATE TRIGGER prompt_search_au AFTER UPDATE ON prompt_search BEGIN
    INSERT INTO prompts_fts(prompts_fts, rowid, title, body, tags)
    VALUES ('delete', old.rowid, old.title, old.body, old.tags);
    INSERT INTO prompts_fts(rowid, title, body, tags)
    VALUES (new.rowid, new.title, new.body, new.tags);
END;
