-- VENDORED FIXTURE — do not edit by hand.
-- Source: chaingate-ops collector/dump_schema.py
-- Regenerate workflow: see chaingate-ops docs/COLLECTOR_RUNBOOK.md
CREATE TABLE packages (
    id           INTEGER PRIMARY KEY,
    ecosystem    TEXT NOT NULL CHECK (ecosystem = 'npm'),
    package_name TEXT NOT NULL,
    UNIQUE (ecosystem, package_name)
);

CREATE TABLE versions (
    id                          INTEGER PRIMARY KEY,
    package_id                  INTEGER NOT NULL REFERENCES packages(id),
    version                     TEXT NOT NULL,
    published_at                TEXT,
    content_hash                TEXT,
    content_hash_algo           TEXT,
    integrity_hash              TEXT,
    git_head                    TEXT,
    package_size_bytes          INTEGER,
    dependency_count            INTEGER,
    dependencies                TEXT,
    dev_dependencies            TEXT,
    peer_dependencies           TEXT,
    optional_dependencies       TEXT,
    bundled_dependencies        TEXT,
    dev_dependency_count        INTEGER,
    peer_dependency_count       INTEGER,
    optional_dependency_count   INTEGER,
    bundled_dependency_count    INTEGER,
    publisher_name              TEXT,
    publisher_email             TEXT,
    publisher_tool              TEXT,
    maintainers                 TEXT,
    publish_method              TEXT,
    provenance_present          INTEGER,
    provenance_details          TEXT,
    has_install_scripts         INTEGER,
    source_repo_url             TEXT,
    license                     TEXT,
    first_observed_at           TEXT,
    last_seen_at                TEXT,
    provenance_source           TEXT NOT NULL DEFAULT 'collected'
                                 CHECK (provenance_source IN ('collected', 'reconstructed')),
    UNIQUE (package_id, version)
);

CREATE TABLE version_files (
    id                INTEGER PRIMARY KEY,
    version_id        INTEGER NOT NULL REFERENCES versions(id),
    filename          TEXT NOT NULL,
    packagetype       TEXT,
    content_hash      TEXT,
    content_hash_algo TEXT,
    size_bytes        INTEGER,
    uploaded_at       TEXT,
    url               TEXT,
    first_observed_at TEXT,
    last_seen_at      TEXT,
    UNIQUE (version_id, filename)
);

CREATE TABLE gate_decisions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    version      TEXT NOT NULL,
    disposition  TEXT NOT NULL CHECK (disposition IN ('ALLOW','WARN','BLOCK')),
    gates_fired  TEXT NOT NULL,
    decided_at   TEXT DEFAULT (datetime('now'))
);

CREATE TABLE overrides (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    version      TEXT NOT NULL,
    reason       TEXT NOT NULL,
    created_at   TEXT DEFAULT (datetime('now')),
    UNIQUE (package_name, version)
);

CREATE TABLE seed_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE dep_first_publish (
    package_name  TEXT PRIMARY KEY,
    first_publish TEXT,
    status        TEXT NOT NULL CHECK (status IN ('ok','vanished','error')),
    cached_at     TEXT NOT NULL DEFAULT (datetime('now')),
    attempts      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE attack_labels (
    id                     INTEGER PRIMARY KEY,
    package_id             INTEGER NOT NULL REFERENCES packages(id),
    version_id             INTEGER REFERENCES versions(id),
    is_malicious           INTEGER NOT NULL CHECK (is_malicious IN (0, 1)),
    attack_name            TEXT,
    source                 TEXT,
    advisory_id            TEXT,
    aliases                TEXT,
    severity               TEXT,
    summary                TEXT,
    affected_range         TEXT,
    url                    TEXT,
    modified_at            TEXT,
    advisory_published_at  TEXT,
    detection_lag_days     INTEGER,
    provenance_source      TEXT NOT NULL DEFAULT 'collected'
                            CHECK (provenance_source IN ('collected', 'reconstructed'))
);

CREATE INDEX idx_versions_pkg      ON versions(package_id);
CREATE INDEX idx_versions_pub_at   ON versions(package_id, published_at DESC);
CREATE INDEX idx_vfiles_ver        ON version_files(version_id);
CREATE INDEX idx_decisions_pkg_ver ON gate_decisions(package_name, version);
CREATE INDEX idx_decisions_at      ON gate_decisions(decided_at DESC);
CREATE UNIQUE INDEX idx_overrides  ON overrides(package_name, version);
CREATE INDEX idx_attack_labels_pkg ON attack_labels(package_id);
CREATE INDEX idx_attack_labels_ver ON attack_labels(version_id);
CREATE INDEX idx_attack_labels_mal ON attack_labels(is_malicious) WHERE is_malicious = 1;
CREATE UNIQUE INDEX idx_attack_labels_adv_pkg_pkglvl
    ON attack_labels(advisory_id, package_id)
    WHERE advisory_id IS NOT NULL AND version_id IS NULL;
CREATE UNIQUE INDEX idx_attack_labels_adv_pkg_verlvl
    ON attack_labels(advisory_id, package_id, version_id)
    WHERE advisory_id IS NOT NULL AND version_id IS NOT NULL;
CREATE INDEX idx_versions_reconstructed
    ON versions(provenance_source)
    WHERE provenance_source = 'reconstructed';
CREATE INDEX idx_attack_labels_reconstructed
    ON attack_labels(provenance_source)
    WHERE provenance_source = 'reconstructed';
