# OSINT-Lite v2.0

<p align="center">
  <b>Lightweight OSINT tools optimized for Termux & Linux environments.</b>
</p>

---

## 🚀 Features

* **PhoneIntel (`--phone` / `--phone-social`):** 
  * Identifies Indonesian cellular providers (Telkomsel, XL/Axis, Indosat, Tri, Smartfren).
  * Validates formatting and performs online lookup (via API layer).
  * Automatically scans common public social media accounts using pattern-based detection derived from phone numbers.
* **EmailScan (`--email`):** 
  * Validates email formatting.
  * Checks public data breach databases (Have I Been Pwned integration via proxy).
  * Performs username footprint enumeration across major platforms.
* **MetaGrab (`--meta`):** 
  * Advanced photo forensics and metadata extraction.
  * Generates MD5 & SHA256 file hashes.
  * Automatically detects social media origins (Facebook, WhatsApp, Instagram stripping patterns).
  * Extracts camera/hardware specifications (Make, Model, Lens, ISO, Exposure, Date).
  * Automatically parses GPS coordinates and generates direct Google Maps links.
  * Includes a built-in Privacy Risk Assessment analyzer.

---

## 📦 Prerequisites

Make sure you have Python 3 installed along with the required dependencies:

```bash
pkg update && pkg install python git -y  # Untuk pengguna Termux
pip install requests exifread


## ⚙️ Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/semb-commits/termux-osint-tool.git
cd termux-osint-tool
chmod +x "osint lite.py"
