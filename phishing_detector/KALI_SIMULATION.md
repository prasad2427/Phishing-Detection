# Kali Linux Phishing Simulation Guide

Follow these steps to generate test data for the PhishGuard AI Detector.

## Step 1 — Install Simulation Tools
Run these commands in your Kali Linux terminal:
```bash
sudo apt update
sudo apt install -y gophish set qrencode scrot
```

## Step 2 — Generate Phishing URL using SET
1. Launch the Social-Engineer Toolkit:
   ```bash
   sudo setoolkit
   ```
2. Choose: `1` (Social Engineering) → `2` (Website Attacks) → `3` (Credential Harvester) → `2` (Site Cloner)
3. Enter your Kali IP when prompted.
4. Clone a site (e.g., `https://www.facebook.com`).
5. **Target URL**: `http://YOUR-KALI-IP/`

## Step 3 — Generate Phishing QR Code
Generate a QR code pointing to your phishing payload:
```bash
qrencode -o phishing_qr.png 'http://YOUR-KALI-IP/login-verify'
```

## Step 4 — Screenshot Analysis
1. Open your phishing page in a Kali browser:
   ```bash
   firefox http://YOUR-KALI-IP/ &
   ```
2. Capture the UI:
   ```bash
   scrot phishing_screenshot.png
   ```

## Step 5 — Transfer Files (Kali → Windows)
### Option A: Python HTTP Server
```bash
# On Kali
python3 -m http.server 8080
```
Then visit `http://KALI-IP:8080` from your host machine to download the files.

### Option B: Shared Folders
Configure via VMware/VirtualBox settings: `Settings → Options → Shared Folders → Add`.
