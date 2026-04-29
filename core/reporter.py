import os
import sqlite3
from datetime import datetime
from textwrap import wrap
from fpdf import FPDF
from core import db


def safe_text(text, max_len=120):
    """Clean and truncate text; keep ASCII only."""
    if not text:
        return ""
    text = str(text).replace("\n", " ").replace("→", "->").replace("•", "-")
    text = text.encode("ascii", "ignore").decode("ascii")
    return (text[:max_len] + "...") if len(text) > max_len else text


def wrapped(pdf, text, width=90, line_height=6):
    """Write wrapped text safely to PDF."""
    for line in wrap(safe_text(text), width):
        pdf.cell(0, line_height, line, ln=True)


def generate_report(case_path, investigator="Investigator1"):
    """Generate an ASCII-only, width-safe forensic report PDF."""
    db_path = os.path.join(case_path, "case.db")

    # --- gather data ---
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    evidence = list(c.execute("SELECT filename, path, size, sha256, created_utc FROM evidence"))
    actions = list(c.execute("SELECT ts_utc, actor, action_type, target FROM actions"))
    chain_blocks = list(c.execute("SELECT block_index, ts_utc, action_id, prev_hash, block_hash FROM chain"))
    conn.close()

    verified, blocks = db.verify_chain(db_path)

    # --- PDF setup ---
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_left_margin(15)
    pdf.set_right_margin(15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "ForensicVault Case Report", ln=True, align="C")
    pdf.ln(6)

    pdf.set_font("Helvetica", "", 11)
    wrapped(pdf, f"Generated: {datetime.utcnow().isoformat()} UTC")
    wrapped(pdf, f"Investigator: {investigator}")
    wrapped(pdf, f"Case Path: {case_path}")
    wrapped(pdf, f"Chain Verification: {'VALID' if verified else 'TAMPERED'} ({blocks} blocks)")
    pdf.ln(8)

    # --- Evidence ---
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Evidence Collected:", ln=True)
    pdf.set_font("Helvetica", "", 10)

    if not evidence:
        wrapped(pdf, "No evidence collected.")
    else:
        for f, p, s, h, t in evidence:
            wrapped(pdf, f"- File: {f}")
            wrapped(pdf, f"  Path: {p}")
            wrapped(pdf, f"  Size: {s} bytes")
            wrapped(pdf, f"  Hash: {h}")
            wrapped(pdf, f"  Created: {t}")
            pdf.ln(3)

    pdf.ln(5)

    # --- Actions ---
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Actions & Analysis:", ln=True)
    pdf.set_font("Helvetica", "", 10)

    if not actions:
        wrapped(pdf, "No actions recorded.")
    else:
        for ts, actor, act, target in actions:
            line = f"[{ts}] {actor} -> {act} -> {target}"
            wrapped(pdf, line)
    pdf.ln(5)

    # --- Chain ---
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Custody Chain:", ln=True)
    pdf.set_font("Helvetica", "", 9)

    if not chain_blocks:
        wrapped(pdf, "No chain entries.")
    else:
        for idx, ts, aid, prevh, bh in chain_blocks:
            wrapped(pdf, f"#{idx} | {ts}")
            wrapped(pdf, f"Prev: {prevh[:40]} -> Hash: {bh[:40]}")
            pdf.ln(2)

    pdf.ln(6)

    # --- save file ---
    export_dir = os.path.join(case_path, "exports")
    os.makedirs(export_dir, exist_ok=True)
    out_path = os.path.join(
        export_dir, f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    )
    pdf.output(out_path, "F")

    return out_path, verified, blocks
