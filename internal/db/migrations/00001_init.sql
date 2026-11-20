-- +goose Up
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------- CVEs
CREATE TABLE cves (
    id              text PRIMARY KEY,                 -- CVE-YYYY-NNNN
    title           text,
    description     text NOT NULL DEFAULT '',
    cvss            numeric(3,1),
    cvss_version    text,
    cvss_vector     text,
    cvss_source     text,              -- nvd, cna, osv
    severity        text NOT NULL DEFAULT 'unknown',  -- none, low, medium, high, critical, unknown
    cwe             text[] NOT NULL DEFAULT '{}',
    kev             boolean NOT NULL DEFAULT false,
    kev_added       date,
    kev_due         date,
    kev_action      text,
    epss            double precision,
    epss_percentile double precision,
    references_     text[] NOT NULL DEFAULT '{}',
    state           text NOT NULL DEFAULT 'PUBLISHED',  -- PUBLISHED, REJECTED
    sources         text[] NOT NULL DEFAULT '{}',
    published       timestamptz,
    modified        timestamptz,
    ingested_at     timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    search          tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector('english', id), 'A') ||
        setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('english', description), 'B')
    ) STORED
);
CREATE INDEX cves_search_idx ON cves USING gin (search);
CREATE INDEX cves_published_idx ON cves (published DESC);
CREATE INDEX cves_modified_idx ON cves (modified DESC);
CREATE INDEX cves_severity_idx ON cves (severity);
CREATE INDEX cves_kev_idx ON cves (kev) WHERE kev;
CREATE INDEX cves_cwe_idx ON cves USING gin (cwe);

CREATE TABLE cve_embeddings (
    cve_id     text PRIMARY KEY REFERENCES cves(id) ON DELETE CASCADE,
    embedding  vector(768) NOT NULL,
    model      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cve_embeddings_hnsw ON cve_embeddings USING hnsw (embedding vector_cosine_ops);

CREATE TABLE cve_ai (
    cve_id      text PRIMARY KEY REFERENCES cves(id) ON DELETE CASCADE,
    category    text,
    summary_en  text,
    model       text NOT NULL,
    input_hash  text NOT NULL,     -- hash of the description used, re-run when it changes
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- products
CREATE TABLE products (
    id          bigserial PRIMARY KEY,
    vendor      text NOT NULL DEFAULT '',
    name        text NOT NULL,
    ecosystem   text NOT NULL,             -- cpe, npm, PyPI, Go, ...
    cpe         text UNIQUE,               -- cpe:2.3:a:vendor:product
    purl        text UNIQUE,               -- pkg:npm/express
    aliases     text[] NOT NULL DEFAULT '{}',
    cve_count   integer NOT NULL DEFAULT 0, -- for autocomplete ranking
    search_text text GENERATED ALWAYS AS (lower(vendor || ' ' || name)) STORED,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX products_trgm_idx ON products USING gin (search_text gin_trgm_ops);
CREATE INDEX products_name_idx ON products (lower(name));
CREATE INDEX products_aliases_idx ON products USING gin (aliases);

CREATE TABLE cve_affects (
    id                       bigserial PRIMARY KEY,
    cve_id                   text NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    product_id               bigint NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    source                   text NOT NULL,     -- nvd, osv, cna
    version_start_including  text,
    version_start_excluding  text,
    version_end_including    text,
    version_end_excluding    text,
    versions                 text[] NOT NULL DEFAULT '{}',
    all_versions             boolean NOT NULL DEFAULT false,
    confirmed                boolean NOT NULL DEFAULT true
);
CREATE INDEX cve_affects_cve_idx ON cve_affects (cve_id);
CREATE INDEX cve_affects_product_idx ON cve_affects (product_id);

-- ---------------------------------------------------------------- users & auth
CREATE TABLE users (
    id          bigserial PRIMARY KEY,
    email       text NOT NULL UNIQUE,
    verified    boolean NOT NULL DEFAULT false,
    role        text NOT NULL DEFAULT 'user',   -- user, admin
    plan        text NOT NULL DEFAULT 'free',   -- free, plus
    webauthn_id bytea NOT NULL DEFAULT gen_random_bytes(32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_login  timestamptz
);

CREATE TABLE sessions (
    token_hash  bytea PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    ip          text,
    user_agent  text
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE magic_links (
    token_hash  bytea PRIMARY KEY,
    email       text NOT NULL,
    purpose     text NOT NULL,     -- register, login
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);

CREATE TABLE passkeys (
    id            bigserial PRIMARY KEY,
    user_id       bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          text NOT NULL DEFAULT 'Passkey',
    credential_id bytea NOT NULL UNIQUE,
    credential    jsonb NOT NULL,   -- go-webauthn Credential
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);

CREATE TABLE webauthn_sessions (
    id          text PRIMARY KEY,
    user_id     bigint REFERENCES users(id) ON DELETE CASCADE,
    data        jsonb NOT NULL,
    expires_at  timestamptz NOT NULL
);

CREATE TABLE api_keys (
    id           bigserial PRIMARY KEY,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         text NOT NULL,
    prefix       text NOT NULL,
    key_hash     bytea NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);

-- ---------------------------------------------------------------- stacks
CREATE TABLE stacks (
    id          bigserial PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX stacks_user_idx ON stacks (user_id);

CREATE TABLE stack_items (
    id          bigserial PRIMARY KEY,
    stack_id    bigint NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    product_id  bigint NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    version     text NOT NULL DEFAULT '',    -- '' = all versions
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (stack_id, product_id, version)
);
CREATE INDEX stack_items_product_idx ON stack_items (product_id);

CREATE TABLE stack_cve_status (
    stack_id    bigint NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    cve_id      text NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    status      text NOT NULL,     -- not_affected, patched
    note        text,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (stack_id, cve_id)
);

CREATE TABLE matches (
    id          bigserial PRIMARY KEY,
    cve_id      text NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    stack_id    bigint NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    reason      text NOT NULL,
    confirmed   boolean NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cve_id, stack_id)
);
CREATE INDEX matches_stack_idx ON matches (stack_id);

-- ---------------------------------------------------------------- notifications
CREATE TABLE channels (
    id            bigserial PRIMARY KEY,
    user_id       bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type          text NOT NULL,
    class         text NOT NULL DEFAULT 'free',  -- free, paid
    name          text NOT NULL,
    config        bytea NOT NULL,                -- envelope encrypted JSON
    verified      boolean NOT NULL DEFAULT false,
    enabled       boolean NOT NULL DEFAULT true,
    verify_token  bytea,                         -- hash, email double opt-in
    unsub_token   text NOT NULL DEFAULT encode(gen_random_bytes(24), 'hex'),
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX channels_user_idx ON channels (user_id);

CREATE TABLE notification_rules (
    id                  bigserial PRIMARY KEY,
    stack_id            bigint NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    channel_id          bigint NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    min_cvss            numeric(3,1) NOT NULL DEFAULT 0,
    kev_only            boolean NOT NULL DEFAULT false,
    min_epss            double precision NOT NULL DEFAULT 0,
    mode                text NOT NULL DEFAULT 'instant',   -- instant, hourly, daily
    quiet_start         text,      -- HH:MM
    quiet_end           text,
    timezone            text NOT NULL DEFAULT 'UTC',
    include_unconfirmed boolean NOT NULL DEFAULT true,
    enabled             boolean NOT NULL DEFAULT true,
    last_digest_at      timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (stack_id, channel_id)
);

CREATE TABLE deliveries (
    id               bigserial PRIMARY KEY,
    match_id         bigint REFERENCES matches(id) ON DELETE SET NULL,
    cve_id           text NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    stack_id         bigint NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    channel_id       bigint NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    rule_id          bigint REFERENCES notification_rules(id) ON DELETE SET NULL,
    occasion         text NOT NULL,      -- new, kev_added, cvss_raised
    status           text NOT NULL DEFAULT 'pending',  -- pending, digest, sent, failed, suppressed
    attempts         integer NOT NULL DEFAULT 0,
    last_error       text,
    next_attempt_at  timestamptz,
    sent_at          timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cve_id, stack_id, channel_id, occasion)
);
CREATE INDEX deliveries_channel_status_idx ON deliveries (channel_id, status);
CREATE INDEX deliveries_status_idx ON deliveries (status, created_at);

-- ---------------------------------------------------------------- sync state
CREATE TABLE sync_state (
    source        text PRIMARY KEY,
    cursor        text NOT NULL DEFAULT '',
    etag          text,
    last_run      timestamptz,
    last_success  timestamptz,
    last_error    text,
    newest_item   timestamptz,
    items_total   bigint NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------- plus plan (phase 6, prepared)
CREATE TABLE credit_ledger (
    id          bigserial PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        text NOT NULL,     -- topup, reserve, charge, refund
    amount      integer NOT NULL,  -- positive = credit, negative = debit
    delivery_id bigint REFERENCES deliveries(id) ON DELETE SET NULL,
    note        text,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX credit_ledger_user_idx ON credit_ledger (user_id);

CREATE TABLE channel_prices (
    channel_type text NOT NULL,
    country      text NOT NULL DEFAULT '*',
    credits      integer NOT NULL,
    PRIMARY KEY (channel_type, country)
);

-- +goose Down
DROP TABLE channel_prices, credit_ledger, sync_state, deliveries, notification_rules, channels,
    matches, stack_cve_status, stack_items, stacks, api_keys, webauthn_sessions, passkeys,
    magic_links, sessions, users, cve_affects, products, cve_ai, cve_embeddings, cves;
