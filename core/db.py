import sqlite3
import os
from datetime import datetime
import json
from hashlib import sha256

def init_case_db(case_path: str):
    """Initialize a new case database if not already exists."""
    db_path = os.path.join(case_path, "case.db")
    if os.path.exists(db_path):
        return db_path

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Case metadata
    c.execute("""
    CREATE TABLE IF NOT EXISTS case_meta (
        case_id TEXT PRIMARY KEY,
        title TEXT,
        investigator TEXT,
        created_utc TEXT
    )""")

    # Evidence table
    c.execute("""
    CREATE TABLE IF NOT EXISTS evidence (
        eid INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        path TEXT,
        size INTEGER,
        sha256 TEXT,
        created_utc TEXT
    )""")

    # Actions table
    c.execute("""
    CREATE TABLE IF NOT EXISTS actions (
        aid INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_utc TEXT,
        actor TEXT,
        action_type TEXT,
        target TEXT,
        details_json TEXT
    )""")

    # Chain-of-custody blocks
    c.execute("""
    CREATE TABLE IF NOT EXISTS chain (
        block_index INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_utc TEXT,
        action_id INTEGER,
        prev_hash TEXT,
        block_hash TEXT
    )""")

    conn.commit()
    conn.close()
    return db_path


def log_action(db_path, actor, action_type, target, details_dict):
    """Record an action into the database."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    ts = datetime.utcnow().isoformat()
    c.execute("""
        INSERT INTO actions (ts_utc, actor, action_type, target, details_json)
        VALUES (?, ?, ?, ?, ?)
    """, (ts, actor, action_type, target, json.dumps(details_dict, sort_keys=True)))

    conn.commit()
    aid = c.lastrowid
    conn.close()
    return aid, ts


def get_last_block_hash(db_path):
    """Fetch the last recorded block hash from the chain."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT block_hash FROM chain ORDER BY block_index DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    return row[0] if row else "0" * 64  # genesis hash


def append_block(db_path, action_id, ts_utc, prev_hash, action_json):
    """Append a new custody block to the chain table."""
    record = f"{prev_hash}{ts_utc}{action_json}"
    block_hash = sha256(record.encode()).hexdigest()

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        INSERT INTO chain (ts_utc, action_id, prev_hash, block_hash)
        VALUES (?, ?, ?, ?)
    """, (ts_utc, action_id, prev_hash, block_hash))
    conn.commit()
    conn.close()

    return block_hash

def verify_chain(db_path):
    """Verify the integrity of the custody chain."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Get all chain blocks with corresponding action data
    c.execute("""
    SELECT chain.block_index, chain.ts_utc, chain.prev_hash, chain.block_hash,
           actions.actor, actions.action_type, actions.target, actions.details_json
    FROM chain
    JOIN actions ON chain.action_id = actions.aid
    ORDER BY chain.block_index ASC
    """)
    rows = c.fetchall()
    conn.close()

    prev = "0" * 64
    for i, row in enumerate(rows):
        block_index, ts, prev_hash, blk_hash, actor, action_type, target, details_json = row
        # reconstruct original action_json string
        action_json = json.dumps({
            "actor": actor,
            "action_type": action_type,
            "target": target,
            "details": json.loads(details_json)
        }, sort_keys=True)

        # recompute the same hash logic
        record = f"{prev_hash}{ts}{action_json}"
        expected = sha256(record.encode()).hexdigest()

        if prev_hash != prev or blk_hash != expected:
            return False, block_index  # tampered or inconsistent

        prev = blk_hash

    return True, len(rows)


# def verify_chain(db_path):
#     """Verify the integrity of the custody chain."""
#     conn = sqlite3.connect(db_path)
#     c = conn.cursor()
#     c.execute("SELECT block_index, ts_utc, action_id, prev_hash, block_hash FROM chain ORDER BY block_index ASC")
#     rows = c.fetchall()
#     conn.close()

#     prev = "0" * 64
#     for i, row in enumerate(rows):
#         idx, ts, aid, prev_hash, blk_hash = row
#         expected = sha256(f"{prev_hash}{ts}{aid}".encode()).hexdigest()
#         if prev_hash != prev or blk_hash != expected:
#             return False, idx
#         prev = blk_hash
#     return True, len(rows)
