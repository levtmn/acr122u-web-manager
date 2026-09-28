#!/usr/bin/env python3
"""
FastAPI web server for RFID Manager (ACR122U read/write/clone).

Run from project root:
    python3 web/app.py

Access at http://device.local:8030
Started on demand by rfid-launcher (port 8029) — not enabled at boot.
"""

import re
import sqlite3
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).parent.parent
DATA = ROOT / "data"
DUMPS = DATA / "dumps"
DB_PATH = DATA / "rfid.db"
DUMPS.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="RFID Manager")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    """Cheap liveness probe for the launcher — must NOT touch the reader, so
    it stays instant even while /api/status is busy cycling pcscd."""
    return {"ok": True}


# ── sqlite index ────────────────────────────────────────────────────────────

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id TEXT PRIMARY KEY,
            name TEXT,
            uid TEXT,
            card_type TEXT,
            mode TEXT,
            atqa TEXT,
            sak TEXT,
            filename TEXT,
            created_at TEXT
        )
    """)
    conn.row_factory = sqlite3.Row
    return conn


# ── card type detection (from SAK, NXP AN10834 table) ─────────────────────

SAK_TYPES = {
    "08": "MIFARE Classic 1K",
    "18": "MIFARE Classic 4K",
    "09": "MIFARE Mini",
    "00": "MIFARE Ultralight/NTAG",
    "20": "MIFARE DESFire / ISO14443-4",
    "28": "MIFARE SmartMX / ISO14443-4",
}


def guess_type(sak: str | None) -> str:
    if not sak:
        return "Unknown"
    return SAK_TYPES.get(sak.upper().strip(), f"Unknown (SAK {sak})")


# ── reader/USB presence ─────────────────────────────────────────────────────

ACR122U_USB_ID = "072f:2200"


def reader_present() -> bool:
    r = subprocess.run(["lsusb", "-d", ACR122U_USB_ID], capture_output=True, text=True)
    return bool(r.stdout.strip())


# ── libnfc exclusive-access mode switch ────────────────────────────────────
#
# pcscd and libnfc's CLI tools (nfc-list/mfoc/nfc-mfclassic/nfc-mfultralight)
# cannot hold the ACR122U USB device at the same time. Reliable detection of
# Mifare Classic in particular requires libnfc's low-level anticollision
# access — pyscard/pcscd's connect() negotiation is flaky for non-ISO14443-4
# memory cards on this reader (confirmed: intermittent "Card is unresponsive"
# / "Card protocol mismatch" even with a card correctly seated, while
# `nfc-list` reads the same card every time). So libnfc is used for ALL
# reads — pcscd is stopped for the duration of every scan and restarted
# immediately after.
#
# A process-wide lock serializes overlapping requests so two stop/start
# cycles never race each other.

# Process-local: assumes a single uvicorn worker (see __main__). With more than
# one worker this no longer serializes pcscd stop/start across requests, and two
# concurrent operations could race the reader.
_nfc_lock = threading.Lock()


class ExclusiveNFC:
    def __enter__(self):
        _nfc_lock.acquire()
        subprocess.run(
            ["sudo", "/usr/bin/systemctl", "stop", "pcscd.service", "pcscd.socket"],
            check=True,
        )
        time.sleep(0.2)
        return self

    def __exit__(self, exc_type, exc, tb):
        subprocess.run(
            ["sudo", "/usr/bin/systemctl", "start", "pcscd.socket", "pcscd.service"],
            check=False,
        )
        _nfc_lock.release()
        return False


def run(cmd, timeout=None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ── intercom key cloning — copy access keys onto magic cards ────────────────
#
# How intercom keys actually work (learned the hard way):
#
#  * Most doors read only the 4-byte UID at the anticollision layer, like a
#    Dallas/iButton serial. Those keys have BLANK, factory-key (FFFFFFFF)
#    sectors. A plain UID copy onto a magic card opens those doors.
#
#  * Some doors ALSO authenticate to / read secret sector data protected by
#    CUSTOM keys. A bald UID copy does NOT open those, and the ACR122U cannot
#    recover the custom keys (dictionary + darkside both failed; that needs a
#    Proxmark3). We still offer a UID-only attempt but warn it will probably
#    fail on such doors.
#
# So on read we grab the UID AND try a full default-key dump: if all 64
# blocks read, the source is UID-only-style and we clone its real contents;
# if not, we fall back to a synthetic UID-only dump and flag the risk.
#
# Target (blank) cards come in two "magic" flavours:
#   * Gen1a "UID"  — rewrite block 0 via a secret backdoor unlock frame.
#   * Gen2 "CUID"  — rewrite block 0 with a normal authenticated write.
# We auto-detect (probe the Gen1a backdoor; if absent, try the CUID write)
# and pick the method. A plain fixed-UID card (block 0 locked) is rejected.
#
# CAVEAT: the ACR122U's firmware relays the Gen1a backdoor unreliably — it
# often fails a few times, then works after the card is physically lifted
# and reseated. A failed write is therefore not proof of a bad card; the UI
# prompts a reseat + retry before giving up.


def build_uid_dump(uid_hex: str, atqa_hex: str | None, sak_hex: str | None) -> bytes:
    uid = bytes.fromhex(uid_hex)
    bcc = 0
    for b in uid:
        bcc ^= b
    sak = bytes.fromhex(sak_hex) if sak_hex else bytes.fromhex("08")
    atqa = bytes.fromhex(atqa_hex) if atqa_hex else bytes.fromhex("0004")
    block0 = uid + bytes([bcc]) + sak + atqa + bytes(8)
    trailer = (
        bytes.fromhex("FFFFFFFFFFFF")  # key A (factory default)
        + bytes.fromhex("FF0780")       # access bits (factory default)
        + bytes.fromhex("69")           # GPB
        + bytes.fromhex("FFFFFFFFFFFF")  # key B (factory default)
    )
    data = bytearray(1024)
    data[0:16] = block0
    for block in range(1, 64):
        if block % 4 == 3:
            data[block * 16:(block + 1) * 16] = trailer
    return bytes(data)


def _parse_uid(out: str) -> str | None:
    m = re.search(r"UID \(NFCID1\):\s*([0-9A-Fa-f ]+)", out)
    return m.group(1).replace(" ", "").upper() if m else None


class CloneWriteRequest(BaseModel):
    dump_id: str


class RenameRequest(BaseModel):
    name: str


def _key_row(id_):
    conn = db()
    row = conn.execute("SELECT * FROM keys WHERE id = ?", (id_,)).fetchone()
    conn.close()
    return row


@app.get("/api/clone/source")
def clone_source():
    """Read the source key: UID/type, plus a full default-key dump if the
    card allows it. Saves it to the key library and returns its id."""
    if not reader_present():
        return JSONResponse({"ok": False, "message": "ACR122U not connected"}, status_code=409)

    key_id = uuid.uuid4().hex[:8]
    fname = f"key_{key_id}.mfd"
    src_path = DUMPS / fname

    with ExclusiveNFC():
        listing = run(["nfc-list"], timeout=10)
        out = listing.stdout + listing.stderr
        if "ISO/IEC 14443A" not in out:
            full = None
        else:
            full = run(["nfc-mfclassic", "r", "a", "u", str(src_path)], timeout=45)

    uid = _parse_uid(out)
    sak_m = re.search(r"SAK \(SEL_RES\):\s*([0-9A-Fa-f]+)", out)
    atqa_m = re.search(r"ATQA \(SENS_RES\):\s*([0-9A-Fa-f ]+)", out)
    if not uid:
        return JSONResponse({"ok": False, "message": "No card detected"}, status_code=409)

    sak = sak_m.group(1).strip().upper() if sak_m else "08"
    # nfc-list prints ATQA MSB-first (e.g. "00 04"); block 0 stores it LSB-first,
    # so reverse the two bytes when synthesising a dump.
    atqa_disp = atqa_m.group(1).replace(" ", "").upper() if atqa_m else "0004"
    atqa_block = atqa_disp[2:4] + atqa_disp[0:2]
    card_type = guess_type(sak)

    full_out = (full.stdout + full.stderr) if full else ""
    blocks_read = 0
    m = re.search(r"Done,\s*(\d+)\s*of\s*64\s*blocks read", full_out)
    if m:
        blocks_read = int(m.group(1))

    if blocks_read == 64 and src_path.exists():
        mode = "full"  # source is default-keyed; we cloned its real contents
    else:
        # custom-keyed or unreadable → synthesise a UID-only dump
        src_path.write_bytes(build_uid_dump(uid, atqa_block, sak))
        mode = "uid_only"

    conn = db()
    conn.execute(
        "INSERT INTO keys (id, name, uid, card_type, mode, atqa, sak, filename, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (key_id, "", uid, card_type, mode, atqa_disp, sak, fname,
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()

    return {
        "ok": True,
        "dump_id": key_id,
        "uid": uid,
        "type": card_type,
        "mode": mode,
        "warn": None if mode == "full" else
                "This key's sectors are protected with custom keys — the data can't be "
                "read, only the UID will be copied. If the intercom checks sector data "
                "(not just the UID), this copy will not open the door.",
    }


@app.post("/api/clone/write")
def clone_write(req: CloneWriteRequest):
    """Write a saved key's dump onto the target magic card. Auto-detects
    Gen1a (backdoor) vs Gen2/CUID (direct write); rejects fixed-UID cards."""
    row = _key_row(req.dump_id)
    if not row:
        return JSONResponse({"ok": False, "message": "Read the original first"}, status_code=400)
    src_path = DUMPS / row["filename"]
    if not src_path.exists():
        return JSONResponse({"ok": False, "message": "Dump missing — read the key again"}, status_code=400)
    expect = row["uid"].upper()
    probe_path = DATA / "probe.mfd"

    with ExclusiveNFC():
        probe = run(["nfc-mfclassic", "R", "a", "u", str(probe_path)], timeout=12)
        gen1a = "Card unlocked" in (probe.stdout + probe.stderr)
        if gen1a:
            run(["nfc-mfclassic", "W", "a", "u", str(src_path)], timeout=45)
            method = "gen1a"
        else:
            run(["nfc-mfclassic", "w", "A", "u", str(src_path)], timeout=45)
            method = "cuid"
        time.sleep(0.3)
        after = run(["nfc-list"], timeout=10)

    got = _parse_uid(after.stdout + after.stderr)

    if got == expect:
        return {"ok": True, "uid": got, "method": method, "mode": row["mode"]}

    if gen1a:
        return JSONResponse(
            {
                "ok": False, "needs_reseat": True, "current_uid": got,
                "message": "Write not confirmed (the ACR122U sometimes fails the unlock "
                           "command on the first try). Lift the blank off the reader for a "
                           "couple of seconds, put it back, and press Retry.",
            },
            status_code=409,
        )
    return JSONResponse(
        {
            "ok": False, "not_magic": True, "current_uid": got,
            "message": "This blank's UID cannot be rewritten (neither Gen1a nor CUID). "
                       "Cloning needs a 'magic' card (UID/Gen1a or CUID/Gen2).",
        },
        status_code=422,
    )


# ── key library ─────────────────────────────────────────────────────────────

@app.get("/api/keys")
def list_keys():
    conn = db()
    rows = conn.execute(
        "SELECT id, name, uid, card_type, mode, created_at FROM keys ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/keys/{key_id}/rename")
def rename_key(key_id: str, req: RenameRequest):
    conn = db()
    cur = conn.execute("UPDATE keys SET name = ? WHERE id = ?", (req.name.strip(), key_id))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    if not changed:
        return JSONResponse({"ok": False, "message": "no such key"}, status_code=404)
    return {"ok": True}


@app.delete("/api/keys/{key_id}")
def delete_key(key_id: str):
    row = _key_row(key_id)
    if not row:
        return JSONResponse({"ok": False, "message": "no such key"}, status_code=404)
    fpath = DUMPS / row["filename"]
    if fpath.exists():
        fpath.unlink()
    conn = db()
    conn.execute("DELETE FROM keys WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


# ── status ──────────────────────────────────────────────────────────────────
#
# Deliberately cheap: the landing page polls this every few seconds, so it must
# NOT enter ExclusiveNFC (which stops+starts pcscd on every call). It reports
# USB presence of the reader only — via `lsusb`, with no pcscd cycling and no
# card read. Detecting the card actually on the reader requires a real libnfc
# scan, which happens on demand when the user reads a key (/api/clone/source).

@app.get("/api/status")
def status():
    return {"reader": reader_present()}


app.mount("/", StaticFiles(directory=str(ROOT / "web" / "static"), html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    # Single worker only. The pcscd stop/start serialization relies on the
    # module-level _nfc_lock, which is process-local — running multiple workers
    # would let two requests cycle pcscd concurrently and race the reader.
    uvicorn.run(app, host="0.0.0.0", port=8030)
