import os
import hashlib
from datetime import datetime
from core import db, integrity


# ============================================================
# Utility: File Hasher
# ============================================================
def hash_file(file_path):
    """Compute SHA-256 hash of a file in streaming mode."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


# ============================================================
# Collect Generic Evidence File
# ============================================================
def collect_evidence(case_path, actor, file_path):
    """Hash file, record metadata, and log custody entry."""
    db_path = os.path.join(case_path, "case.db")

    stat = os.stat(file_path)
    created = datetime.utcfromtimestamp(stat.st_ctime).isoformat()
    modified = datetime.utcfromtimestamp(stat.st_mtime).isoformat()
    size = stat.st_size
    sha256 = hash_file(file_path)
    fname = os.path.basename(file_path)

    # Store metadata
    conn = db.sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO evidence (filename, path, size, sha256, created_utc)
        VALUES (?, ?, ?, ?, ?)
        """,
        (fname, file_path, size, sha256, created),
    )
    conn.commit()
    conn.close()

    # Log in custody chain
    details = {
        "filename": fname,
        "path": file_path,
        "size": size,
        "sha256": sha256,
        "created": created,
        "modified": modified,
    }
    block_hash, ts = integrity.record_chain_event(
        db_path, actor, "add_evidence", fname, details
    )

    return {
        "filename": fname,
        "sha256": sha256,
        "size": size,
        "timestamp": ts,
        "block_hash": block_hash,
    }


# ============================================================
# Collect System / Cloud Logs (Modular Stub)
# ============================================================
def collect_logs(case_path, actor, system_type, log_path):
    """
    Simulates acquisition and hashing of system/cloud logs.
    system_type examples: 'windows_event', 'linux_syslog', 'aws_cloudtrail'
    """
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")

    db_path = os.path.join(case_path, "case.db")
    fname = os.path.basename(log_path)
    sha256 = hash_file(log_path)
    size = os.path.getsize(log_path)

    details = {
        "system_type": system_type,
        "log_path": log_path,
        "sha256": sha256,
        "size": size,
    }

    block_hash, ts = integrity.record_chain_event(
        db_path, actor, "collect_log", f"{system_type}:{fname}", details
    )

    return {
        "filename": fname,
        "type": f"{system_type} Log",
        "sha256": sha256,
        "timestamp": ts,
        "block_hash": block_hash,
    }


# ============================================================
# Simulate Memory Capture (Volatile Data Acquisition)
# ============================================================
def simulate_memory_capture(case_path, actor):
    """
    Creates a dummy binary 'memory dump' file to demonstrate
    volatile data capture and logs it into the custody chain.
    """
    dump_path = os.path.join(case_path, "memory_dump.bin")
    with open(dump_path, "wb") as f:
        f.write(os.urandom(512 * 1024))  # 512 KB fake dump

    info = collect_evidence(case_path, actor, dump_path)
    info["type"] = "Simulated Memory Dump"
    return info


def scan_directory(case_path, actor, target_folder):
    """
    Recursively scan a folder, hash each file, and record to the custody chain.
    Acts as a logical 'disk imaging' / file-system parsing simulation.
    """
    if not os.path.exists(target_folder):
        raise FileNotFoundError(f"Directory not found: {target_folder}")

    db_path = os.path.join(case_path, "case.db")
    summary = {"total_files": 0, "total_size": 0, "records": []}

    for root, _, files in os.walk(target_folder):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                stat = os.stat(fpath)
                size = stat.st_size
                sha256 = hash_file(fpath)

                details = {
                    "filename": fname,
                    "path": fpath,
                    "size": size,
                    "sha256": sha256,
                    "scanned_at": datetime.utcnow().isoformat(),
                }

                # Log to chain
                integrity.record_chain_event(
                    db_path, actor, "scan_file", fname, details
                )

                summary["total_files"] += 1
                summary["total_size"] += size
                summary["records"].append(
                    {"file": fname, "hash": sha256, "size": size}
                )
            except Exception as e:
                print(f"[!] Skipped {fpath}: {e}")

    return summary