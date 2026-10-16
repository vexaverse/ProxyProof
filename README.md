# ProxyProof — Bluetooth Attendance Demo

A runnable Flask + SQLite prototype for the tech-club interview brief.

## Features
- Organiser and student login roles
- Organiser can start a timed attendance session and close it
- Short-lived rotating 10-character tokens (rotate every 5 seconds)
- Student browser/device binding; one device per student account
- Attendance is accepted only for an active session and a fresh token
- Duplicate attendance prevention and one student per device per session
- Manual add/remove attendance, attendance history and percentage summary
- CSV export for organisers
- Auto-refreshing dashboards

## Run locally

Python 3.10+ recommended.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

## Demo accounts
- Organiser: `organiser` / `organiser123`
- Student: `student1` / `student123`
- Student: `student2` / `student123`

Use an incognito window or another browser profile to demo a student and organiser at once.

## Demo flow
1. Sign in as organiser and start a 5-minute session.
2. Open a separate browser profile and sign in as `student1`.
3. Click **Register this device** once.
4. Copy the current rotating token from the organiser dashboard into the student form.
5. Mark attendance and return to the organiser dashboard to see the mark.
6. Try using an old token, binding another account to the same device ID, or marking twice.
7. Export the CSV report.

## Important scope and security notes
This is a **web prototype**, not a finished native Bluetooth Low Energy (BLE) app. Token entry simulates receiving the organiser's BLE broadcast. A browser form cannot prove physical proximity: RSSI is a demo placeholder, and client-supplied device IDs can be spoofed by a determined attacker. For a production build, implement BLE advertising/scanning in native Android/iOS code, signed tokens with server-side nonce tracking, device keys stored in Android Keystore/iOS Keychain, TLS, rate limiting, audit logs, admin-approved device resets, and stronger proximity checks. RSSI alone is not cryptographic proof of location.

The rotating token is derived using the app secret for this local demo. Set a strong random `PROXYPROOF_SECRET` environment variable before any shared deployment. Change demo passwords and disable Flask debug mode outside local development. This project is for demonstration and should not be used to record real attendance without further security review.
