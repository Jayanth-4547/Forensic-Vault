import os
import re
import magic
from datetime import datetime
from core import db, integrity


# ============================================================
# Utility: Detect file type (for filtering and smarter parsing)
# ============================================================
def detect_type(file_path):
    """Detect file type using magic; fallback to file extension."""
    try:
        return magic.from_file(file_path, mime=True)
    except Exception:
        return os.path.splitext(file_path)[1].lower()


# ============================================================
# Text-based Keyword Search
# ============================================================
def keyword_search(file_path, keywords):
    """
    Search for user-provided keywords inside text-based files.
    Returns a list of {keyword, count}.
    """
    results = []
    if not keywords:
        return results

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for kw in keywords:
                matches = [m.start() for m in re.finditer(re.escape(kw), content, re.IGNORECASE)]
                if matches:
                    results.append({"keyword": kw, "count": len(matches)})
    except Exception as e:
        print(f"[!] Skipping non-text file: {file_path} ({e})")

    return results


# ============================================================
# Binary Carving – Detect JPEG/PNG Headers
# ============================================================
def binary_carving(file_path):
    """
    Detect JPEG and PNG binary signatures inside the file.
    Used to identify hidden or embedded data fragments.
    """
    findings = []
    try:
        with open(file_path, "rb") as f:
            data = f.read()

            jpg_matches = [m.start() for m in re.finditer(b"\xFF\xD8\xFF", data)]
            png_matches = [m.start() for m in re.finditer(b"\x89PNG\r\n\x1A\n", data)]

            if jpg_matches:
                findings.append({"type": "JPEG_HEADER", "offsets": jpg_matches})
            if png_matches:
                findings.append({"type": "PNG_HEADER", "offsets": png_matches})
    except Exception as e:
        print(f"[!] Carving failed for {file_path}: {e}")

    return findings


# ============================================================
# Deleted File Recovery Simulation
# ============================================================
def deleted_file_recovery_simulation(dummy_fragments_path):
    """
    Simulates deleted file recovery by scanning a dummy 'free space' text file
    for high-value or structured data fragments (like 16-digit IDs).
    Returns a list of recovered fragment info dictionaries.
    """
    if not os.path.exists(dummy_fragments_path):
        return []

    fragments_found = []
    # Regex for 16-digit IDs or credit-card-like patterns
    pattern = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b")

    try:
        with open(dummy_fragments_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            matches = list(pattern.finditer(content))
            if matches:
                fragments_found.append({
                    "type": "ID_FRAGMENT",
                    "count": len(matches),
                    "example": content[matches[0].start():matches[0].end()]
                })
    except Exception as e:
        print(f"[!] Deleted file recovery simulation failed: {e}")

    return fragments_found


# ============================================================
# Core Analyzer Entry Point
# ============================================================
def analyze_evidence(case_path, actor, file_path, keywords):
    """
    Perform analysis (keyword search + carving + deleted recovery),
    then log to chain-of-custody.
    """
    db_path = os.path.join(case_path, "case.db")
    file_type = detect_type(file_path)
    keyword_hits = keyword_search(file_path, keywords)
    carvings = binary_carving(file_path)

    # Run simulated deleted file recovery (looks for dummy file nearby)
    dummy_fragments_path = os.path.join(os.path.dirname(file_path), "deleted_fragments.txt")
    deleted_recovery = deleted_file_recovery_simulation(dummy_fragments_path)

    details = {
        "file_type": file_type,
        "keywords_found": keyword_hits,
        "carvings_found": carvings,
        "deleted_fragments_found": deleted_recovery,
        "analyzed_at": datetime.utcnow().isoformat()
    }

    # Record action in the blockchain-style custody chain
    fname = os.path.basename(file_path)
    block_hash, ts = integrity.record_chain_event(
        db_path, actor, "analyze_file", fname, details
    )

    return {
        "file": fname,
        "type": file_type,
        "keywords": keyword_hits,
        "carvings": carvings,
        "deleted_recovery": deleted_recovery,
        "timestamp": ts,
        "block_hash": block_hash
    }
