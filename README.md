# ACR122U Web Manager

A small web app for reading and cloning intercom keys using USB **ACS ACR122U** NFC reader.

---

## What it does

- **Read** any 13.56 MHz MIFARE Classic key: UID, type, ATQA/SAK.
- **Clone** a key onto a "magic" blank, auto-detecting the blank type:
  - **UID / Gen1a** — rewrite block 0 via the backdoor unlock frame.
  - **CUID / Gen2** — rewrite block 0 with a normal authenticated write.
  - A plain fixed-UID card is detected and rejected (it can't be a clone target).
- **Full clone vs UID-only**, chosen automatically:
  - If the source has factory keys (`FF…FF`), its full contents are dumped and copied.
  - If the source uses custom sector keys, only the UID is copied and the UI
    **warns** it won't open a door that checks sector data.
- **Key library** — every read is saved to a local SQLite DB with a custom name
  you can edit, re-clone, or delete.

---

## What it can't do

- **125 kHz keys (EM-Marine / HID / Indala)** — the ACR122U is 13.56 MHz only. 
- **Custom-keyed MIFARE Classic** (e.g. a door that authenticates to a secret
  sector) — recovering those keys needs a dictionary/darkside/hardnested attack.
  On the ACR122U the dictionary and darkside (`mfcuk`) attacks are slow and
  unreliable; a **Proxmark3** is the right tool.
- **MIFARE DESFire / Plus / hardened chips** — not cloneable by design.

### ACR122U quirks worked around

- The Gen1a backdoor unlock is relayed unreliably by the reader's firmware — it
  often fails a few times, then works after the card is physically reseated. The
  UI detects a failed write and prompts a reseat + retry rather than declaring
  the card bad.
- `pcscd` (PC/SC) and `libnfc` can't hold the USB device at once, and pyscard's
  connect negotiation is flaky for non-ISO14443-4 memory cards on this reader. So
  **all** reads go through `libnfc` (`nfc-list` / `nfc-mfclassic`): the app stops
  `pcscd` for each operation and restarts it after (serialized by a lock).

---

## Architecture

```
Browser ──► device.local/           nginx static landing page (two app cards)
        │
        ├─► device.local:8029       rfid-launcher  (always-on, tiny)
        │       /api/status         USB presence of ACR122U (072f:2200)
        │       /api/launch         start rfid-manager on demand, else error
        │
        └─► device.local:8030       rfid-manager   (started on demand only)
                /health             instant liveness (used by launcher)
                /api/status         reader + card-on-reader state (slow: cycles pcscd)
                /api/clone/source   read + save source key to library
                /api/clone/write    write a saved key onto a magic blank
                /api/keys           list / rename / delete saved keys
```

The **launcher** is enabled at boot; the **manager** is *not* — it only starts
when you click "Start RFID Manager" and the reader is actually plugged in. 
**device.local** is the actual address of the computer that hosts plugged in USB device.

---

## Setup (Debian / Raspberry Pi OS)

Since I used Raspberry Pi 5 for this project, this commands are required:

```bash
sudo apt install libnfc-bin mfoc pcscd pcsc-tools python3-pyscard
pip3 install fastapi uvicorn[standard] pydantic     # if not present system-wide

# services
sudo cp rfid-manager.service rfid-launcher.service /etc/systemd/system/
sudo cp sudoers-rfid-manager /etc/sudoers.d/rfid-manager   # scoped systemctl only
sudo chmod 440 /etc/sudoers.d/rfid-manager
sudo cp 49-rfid-manager-pcsc.rules /etc/polkit-1/rules.d/  # non-interactive pcsc access
sudo systemctl daemon-reload
sudo systemctl enable --now rfid-launcher.service          # manager stays disabled
```

`sudoers-rfid-manager` grants the service account passwordless rights to exactly
three commands (start/stop `pcscd`, start `rfid-manager`) — nothing else.

---

## Security model

This is a personal tool for a **trusted home LAN**, and it's built that way on purpose:

- **No authentication, `CORS: *`, binds `0.0.0.0`.** Anyone who can reach ports `8029`/`8030`  can drive the API, including starting the service and writing a blank card.
  That's an accepted trade-off for a single-user box on a private network. **Do not expose these ports to the internet.** 
- **Least privilege.** The server runs as an unprivileged account; `sudo` is limited by `sudoers-rfid-manager` to exactly three `systemctl` verbs (start/stop `pcscd`, start `rfid-manager`), and PC/SC access is granted by a narrowly-scoped polkit rule.
- **Card data stays local.** Dumps (`*.mfd`) and the SQLite key library live under `data/`, which is `.gitignore`d 

---

## Legal

For copying **your own** access keys. Cloning credentials you are not authorised to duplicate may be illegal in your jurisdiction. Use responsibly.
