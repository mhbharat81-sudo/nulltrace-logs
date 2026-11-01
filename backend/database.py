"""
DuckDB database layer.
Manages the connection, schema creation, and provides a connection factory.

All tables are created with IF NOT EXISTS so schema initialization is idempotent.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

import duckdb

from backend.config import get_settings

# Thread-local storage — each thread gets its own DuckDB connection
_shared_conn = None
_is_readonly = False
_lock = threading.Lock()


def get_db(db_path: Optional[str] = None, read_only: bool = False) -> duckdb.DuckDBPyConnection:
    """Return a thread-safe DuckDB cursor sharing a singleton process connection."""
    global _shared_conn, _is_readonly
    path = db_path or get_settings().db_path
    with _lock:
        if _shared_conn is not None and not read_only and _is_readonly:
            try:
                _shared_conn.close()
            except Exception:
                pass
            _shared_conn = None

        if _shared_conn is None:
            try:
                _shared_conn = duckdb.connect(path, read_only=read_only)
                _is_readonly = read_only
            except Exception:
                _shared_conn = duckdb.connect(path, read_only=True)
                _is_readonly = True
            _shared_conn.execute("PRAGMA threads=4")
        return _shared_conn.cursor()


def close_db() -> None:
    global _shared_conn, _is_readonly
    with _lock:
        if _shared_conn:
            try:
                _shared_conn.close()
            except Exception:
                pass
            _shared_conn = None
            _is_readonly = False


# ── Schema DDL ─────────────────────────────────────────────────────────────────
SCHEMA_SQL = """
-- ── DATASETS ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS datasets (
    dataset_id      VARCHAR PRIMARY KEY,
    filename        VARCHAR NOT NULL,
    file_path       VARCHAR NOT NULL,
    file_size_bytes BIGINT,
    format          VARCHAR,          -- 'json' | 'jsonl'
    status          VARCHAR DEFAULT 'registered',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ── INGESTION METADATA ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ingestion_metadata (
    run_id              VARCHAR PRIMARY KEY,
    dataset_id          VARCHAR NOT NULL,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    total_records       BIGINT DEFAULT 0,
    valid_records       BIGINT DEFAULT 0,
    invalid_records     BIGINT DEFAULT 0,
    duplicate_records   BIGINT DEFAULT 0,
    processed_bytes     BIGINT DEFAULT 0,
    rows_per_second     DOUBLE,
    peak_memory_mb      DOUBLE,
    db_size_bytes       BIGINT,
    status              VARCHAR DEFAULT 'running',
    error_message       VARCHAR,
    FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id)
);

-- ── RAW EVENTS ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    seq_num             BIGINT NOT NULL,        -- 0-based line position (stable ordering)
    event_id            VARCHAR NOT NULL,        -- event.id (UUID)
    dataset_id          VARCHAR NOT NULL,
    timestamp_utc       TIMESTAMPTZ,            -- @timestamp
    event_kind          VARCHAR,                -- event | alert
    event_category      VARCHAR,                -- network | process | file | authentication | registry
    event_action        VARCHAR,                -- process_created | user_logon | ...
    event_outcome       VARCHAR,                -- success | failure | NULL
    event_severity      INTEGER DEFAULT 0,
    dataset_name        VARCHAR,                -- edr.process | edr.network | ...
    host_name           VARCHAR,
    host_ip             VARCHAR,
    host_os_type        VARCHAR,
    user_name           VARCHAR,
    user_domain         VARCHAR,
    agent_id            VARCHAR,
    raw_json            JSON NOT NULL,
    PRIMARY KEY (event_id)
);

CREATE INDEX IF NOT EXISTS idx_events_seq       ON events(seq_num);
CREATE INDEX IF NOT EXISTS idx_events_dataset   ON events(dataset_id);
CREATE INDEX IF NOT EXISTS idx_events_host      ON events(host_name);
CREATE INDEX IF NOT EXISTS idx_events_user      ON events(user_name);
CREATE INDEX IF NOT EXISTS idx_events_category  ON events(event_category);
CREATE INDEX IF NOT EXISTS idx_events_kind      ON events(event_kind);
CREATE INDEX IF NOT EXISTS idx_events_action    ON events(event_action);

-- ── NORMALIZED EVENTS ─────────────────────────────────────────────────────────
-- Flattened extracted fields for fast SQL analytics
CREATE TABLE IF NOT EXISTS normalized_events (
    event_id            VARCHAR PRIMARY KEY,
    seq_num             BIGINT,
    -- Process fields
    process_name        VARCHAR,
    process_pid         INTEGER,
    process_entity_id   VARCHAR,
    process_cmdline     VARCHAR,
    process_exe         VARCHAR,
    process_md5         VARCHAR,
    process_sha256      VARCHAR,
    parent_name         VARCHAR,
    parent_pid          INTEGER,
    -- Network fields
    src_ip              VARCHAR,
    src_port            INTEGER,
    dst_ip              VARCHAR,
    dst_port            INTEGER,
    dst_domain          VARCHAR,
    net_bytes           BIGINT,
    net_protocol        VARCHAR,
    net_direction       VARCHAR,
    net_transport       VARCHAR,
    -- DNS fields
    dns_question        VARCHAR,
    dns_response_code   VARCHAR,
    -- Auth fields
    auth_outcome        VARCHAR,
    logon_type          VARCHAR,
    winlog_event_id     INTEGER,
    -- File fields
    file_path           VARCHAR,
    file_name           VARCHAR,
    file_size           BIGINT,
    file_target_path    VARCHAR,
    -- Registry fields
    registry_path       VARCHAR,
    registry_data       VARCHAR,
    -- Alert fields
    rule_id             VARCHAR,
    rule_name           VARCHAR,
    threat_technique_id VARCHAR,
    threat_technique_nm VARCHAR,
    threat_tactic_nm    VARCHAR,
    -- Labels
    label_synthetic     BOOLEAN DEFAULT FALSE,
    labels_extra_json   JSON,
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_norm_process_entity ON normalized_events(process_entity_id);
CREATE INDEX IF NOT EXISTS idx_norm_src_ip         ON normalized_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_norm_dst_domain     ON normalized_events(dst_domain);
CREATE INDEX IF NOT EXISTS idx_norm_rule_id        ON normalized_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_norm_parent_name    ON normalized_events(parent_name);

-- ── EVENT ENTITIES ────────────────────────────────────────────────────────────
-- Resolved entity references per event
CREATE TABLE IF NOT EXISTS event_entities (
    id              BIGINT,
    event_id        VARCHAR NOT NULL,
    entity_type     VARCHAR NOT NULL,   -- host | user | process | ip | domain | file | registry
    entity_value    VARCHAR NOT NULL,   -- canonical value
    raw_value       VARCHAR,            -- original value before normalization
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_entities_event  ON event_entities(event_id);
CREATE INDEX IF NOT EXISTS idx_entities_type   ON event_entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_value  ON event_entities(entity_value);

-- ── DETECTIONS ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS detections (
    detection_id        VARCHAR PRIMARY KEY,
    rule_id             VARCHAR NOT NULL,
    rule_name           VARCHAR NOT NULL,
    event_id            VARCHAR NOT NULL,
    dataset_id          VARCHAR NOT NULL,
    seq_num             BIGINT,
    timestamp_utc       TIMESTAMPTZ,
    host_name           VARCHAR,
    user_name           VARCHAR,
    severity            INTEGER,
    confidence          DOUBLE DEFAULT 1.0,
    technique_id        VARCHAR,
    technique_name      VARCHAR,
    tactic_name         VARCHAR,
    kill_chain_stage    VARCHAR,
    explanation         TEXT,
    source              VARCHAR DEFAULT 'engine',  -- 'engine' | 'embedded' (pre-labeled)
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_det_rule_id   ON detections(rule_id);
CREATE INDEX IF NOT EXISTS idx_det_dataset   ON detections(dataset_id);
CREATE INDEX IF NOT EXISTS idx_det_host      ON detections(host_name);
CREATE INDEX IF NOT EXISTS idx_det_user      ON detections(user_name);
CREATE INDEX IF NOT EXISTS idx_det_technique ON detections(technique_id);

-- ── DETECTION EVIDENCE ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS detection_evidence (
    id              BIGINT,
    detection_id    VARCHAR NOT NULL,
    event_id        VARCHAR NOT NULL,
    field_name      VARCHAR NOT NULL,
    field_value     VARCHAR,
    evidence_role   VARCHAR,           -- 'matched_field' | 'context'
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
);

-- ── RESOLVED ENTITIES ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS resolved_entities (
    entity_id       VARCHAR PRIMARY KEY,
    entity_type     VARCHAR NOT NULL,
    canonical_value VARCHAR NOT NULL,
    aliases         JSON,
    first_seen_seq  BIGINT,
    last_seen_seq   BIGINT,
    event_count     BIGINT DEFAULT 0
);

-- ── CORRELATION CANDIDATES ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS correlation_candidates (
    candidate_id    VARCHAR PRIMARY KEY,
    detection_id_a  VARCHAR NOT NULL,
    detection_id_b  VARCHAR NOT NULL,
    candidate_basis VARCHAR NOT NULL,   -- 'process_entity' | 'host_user' | 'auth_seq' | ...
    generated_at    TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (detection_id_a) REFERENCES detections(detection_id),
    FOREIGN KEY (detection_id_b) REFERENCES detections(detection_id)
);

CREATE INDEX IF NOT EXISTS idx_cand_a ON correlation_candidates(detection_id_a);
CREATE INDEX IF NOT EXISTS idx_cand_b ON correlation_candidates(detection_id_b);

-- ── CORRELATION RELATIONSHIPS ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS correlation_relationships (
    relationship_id     VARCHAR PRIMARY KEY,
    candidate_id        VARCHAR,
    detection_id_a      VARCHAR NOT NULL,
    detection_id_b      VARCHAR NOT NULL,
    relationship_class  VARCHAR NOT NULL,  -- 'strong' | 'moderate' | 'weak' | 'none'
    score               INTEGER NOT NULL,  -- 0-100
    basis_dimensions    JSON,              -- which dimensions matched
    evidence_fields     JSON,
    explanation         TEXT,
    accepted            BOOLEAN DEFAULT FALSE,
    rejection_reason    VARCHAR,
    FOREIGN KEY (detection_id_a) REFERENCES detections(detection_id),
    FOREIGN KEY (detection_id_b) REFERENCES detections(detection_id)
);

CREATE INDEX IF NOT EXISTS idx_rel_score     ON correlation_relationships(score DESC);
CREATE INDEX IF NOT EXISTS idx_rel_class     ON correlation_relationships(relationship_class);
CREATE INDEX IF NOT EXISTS idx_rel_accepted  ON correlation_relationships(accepted);

-- ── INCIDENTS ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    incident_id             VARCHAR PRIMARY KEY,
    dataset_id              VARCHAR NOT NULL,
    classification          VARCHAR NOT NULL,  -- multi_stage_chain | isolated_alert | ...
    risk_score              DOUBLE DEFAULT 0,
    confidence_score        DOUBLE DEFAULT 0,
    risk_explanation        TEXT,
    confidence_explanation  TEXT,
    detection_count         INTEGER DEFAULT 0,
    affected_hosts          JSON,
    affected_users          JSON,
    techniques              JSON,
    tactics                 JSON,
    first_seen_seq          BIGINT,
    last_seen_seq           BIGINT,
    first_seen_ts           TIMESTAMPTZ,
    last_seen_ts            TIMESTAMPTZ,
    summary                 TEXT,
    report_text             TEXT,
    precomputed_graph       JSON,
    precomputed_timeline    JSON,
    created_at              TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inc_risk     ON incidents(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_inc_class    ON incidents(classification);
CREATE INDEX IF NOT EXISTS idx_inc_dataset  ON incidents(dataset_id);

-- ── INCIDENT DETECTIONS (join) ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incident_detections (
    incident_id     VARCHAR NOT NULL,
    detection_id    VARCHAR NOT NULL,
    join_reason     TEXT,
    PRIMARY KEY (incident_id, detection_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
);

-- ── INCIDENT GRAPH NODES ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incident_graph_nodes (
    node_id         VARCHAR NOT NULL,
    incident_id     VARCHAR NOT NULL,
    node_type       VARCHAR NOT NULL,  -- host | user | process | ip | domain | file | registry | detection
    label           VARCHAR,
    properties      JSON,
    observation     VARCHAR DEFAULT 'observed',  -- observed | inferred | hypothetical
    PRIMARY KEY (node_id, incident_id)
);

-- ── INCIDENT GRAPH EDGES ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incident_graph_edges (
    edge_id         VARCHAR NOT NULL,
    incident_id     VARCHAR NOT NULL,
    source_node_id  VARCHAR NOT NULL,
    target_node_id  VARCHAR NOT NULL,
    edge_type       VARCHAR NOT NULL,
    event_ids       JSON,
    evidence_fields JSON,
    timestamp_utc   TIMESTAMPTZ,
    seq_num         BIGINT,
    correlation_strength VARCHAR,
    explanation     TEXT,
    observation     VARCHAR DEFAULT 'observed',
    PRIMARY KEY (edge_id, incident_id)
);

-- ── REACHABILITY ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reachability (
    id              BIGINT,
    src_host        VARCHAR NOT NULL,
    dst_host        VARCHAR NOT NULL,
    account         VARCHAR,
    auth_event_id   VARCHAR,
    logon_type      VARCHAR,
    auth_succeeded  BOOLEAN,
    first_seen_seq  BIGINT,
    last_seen_seq   BIGINT,
    hop_count       INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_reach_src  ON reachability(src_host);
CREATE INDEX IF NOT EXISTS idx_reach_dst  ON reachability(dst_host);
CREATE INDEX IF NOT EXISTS idx_reach_acct ON reachability(account);

-- ── SCORING RESULTS ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scoring_results (
    scoring_id      VARCHAR PRIMARY KEY,
    incident_id     VARCHAR NOT NULL,
    risk_score      DOUBLE,
    confidence      DOUBLE,
    risk_factors    JSON,
    confidence_factors JSON,
    computed_at     TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);
"""


def init_schema(db_path: Optional[str] = None) -> None:
    """Create all tables — idempotent, safe to call multiple times."""
    try:
        conn = get_db(db_path, read_only=False)
        conn.execute(SCHEMA_SQL)
        conn.commit()
    except Exception:
        pass


def db_size_bytes(db_path: Optional[str] = None) -> int:
    """Return the current size of the DuckDB file on disk."""
    path = db_path or get_settings().db_path
    p = Path(path)
    return p.stat().st_size if p.exists() else 0
