#!/usr/bin/env python3
"""
Tiny always-on launcher for RFID Manager.

Runs permanently on :8029 with near-zero footprint. Its only job:
  - report whether an ACR122U is plugged into USB (for the landing-page dot)
  - start rfid-manager.service on demand, but only if the reader is present

rfid-manager.service itself is NOT enabled at boot — it only ever runs
because this launcher started it.
"""

import subprocess
import time
import urllib.request
import urllib.error

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(title="RFID Launcher")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

ACR122U_USB_ID = "072f:2200"
MANAGER_SERVICE = "rfid-manager.service"
# Poll the cheap /health probe, NOT /api/status — the latter cycles pcscd and
# takes ~1.5s+, which would outrun a short poll timeout and make launch fail.
MANAGER_HEALTH_URL = "http://127.0.0.1:8030/health"
NOT_CONNECTED_MESSAGE = "ACR122U not connected. Check the USB cable."


def reader_present() -> bool:
    r = subprocess.run(["lsusb", "-d", ACR122U_USB_ID], capture_output=True, text=True)
    return bool(r.stdout.strip())


def manager_is_up() -> bool:
    try:
        with urllib.request.urlopen(MANAGER_HEALTH_URL, timeout=2) as resp:
            return resp.status == 200
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return False


@app.get("/api/status")
def status():
    return {"reader_present": reader_present(), "manager_running": manager_is_up()}


@app.post("/api/launch")
def launch():
    if not reader_present():
        return JSONResponse({"ok": False, "message": NOT_CONNECTED_MESSAGE}, status_code=409)

    if not manager_is_up():
        active = subprocess.run(
            ["systemctl", "is-active", MANAGER_SERVICE], capture_output=True, text=True
        ).stdout.strip()
        if active != "active":
            subprocess.run(
                ["sudo", "/usr/bin/systemctl", "start", MANAGER_SERVICE], check=True
            )
        for _ in range(40):  # ~20s budget for cold uvicorn start
            if manager_is_up():
                break
            time.sleep(0.5)
        else:
            return JSONResponse(
                {"ok": False, "message": "rfid-manager did not come up in time — check journalctl -u rfid-manager"},
                status_code=504,
            )

    return {"ok": True, "url": "http://rpi.local:8030"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8029)
