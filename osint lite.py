#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT-Lite v1.1
Author: sdev
Tools: PhoneIntel, EmailScan, MetaGrab (Optimized)
Lightweight OSINT tools for Termux/Linux
"""

import argparse, requests, re, sys
from pathlib import Path
import exifread
import hashlib

# Colors for output
G = '\033[92m' # Green
R = '\033[91m' # Red
Y = '\033[93m' # Yellow
B = '\033[94m' # Blue
W = '\033[0m' # Reset

BANNER = f"""
{B}======================================
  OSINT-Lite v1.1 | Author: sdev
======================================{W}
"""

def phone_intel(number):
    number = re.sub(r'[^0-9+]', '', number)
    if not number.startswith('+'):
        number = '+62' + number.lstrip('0')

    print(f"\n{B}[+] PhoneIntel:{W} {number}")

    patterns = {
        'Telkomsel': r'\+6281[123]|\+6282[123]',
        'XL/Axis': r'\+6281[789]|\+6283',
        'Indosat': r'\+62814|\+62815|\+62816|\+62855|\+62856|\+62857|\+62858',
        'Tri': r'\+62895|\+62896|\+62897|\+62898|\+62899',
        'Smartfren': r'\+62888|\+62889'
    }

    provider = "Unknown"
    for prov, pattern in patterns.items():
        if re.match(pattern, number):
            provider = prov
            break

    print(f" {Y}Provider{W} : {provider}")
    print(f" {Y}Format{W} : Valid" if len(number) >= 11 else f" {Y}Format{W} : {R}Invalid{W}")

    try:
        url = f"http://apilayer.net/api/validate?number={number}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get('valid'):
                print(f" {Y}Line Type{W}: {data.get('line_type', 'N/A')}")
                print(f" {Y}Location{W} : {data.get('location', 'N/A')}")
    except:
        print(f" {Y}Status{W} : {R}Offline check only{W}")

def phone_social_scan(number):
    number = re.sub(r'[^0-9]', '', number)
    short_num = number[-8:]
    usernames = [short_num, f"user{short_num}", f"usr{short_num}"]

    sites = {
        "Instagram": f"https://instagram.com/{'{user}'}",
        "TikTok": f"https://tiktok.com/@{'{user}'}",
        "GitHub": f"https://github.com/{'{user}'}",
        "Twitter/X": f"https://x.com/{'{user}'}",
        "Facebook": f"https://facebook.com/{'{user}'}"
    }

    print(f"\n{B}[+] Social Scan from Phone:{W} {number}\n")

    found = False
    for user in usernames:
        print(f"{Y}[*]{W} Checking username: {user}")
        for site, url in sites.items():
            try:
                r = requests.get(url.format(user=user), timeout=4)
                if r.status_code == 200:
                    print(f" {G}[FOUND]{W} {site}: {url.format(user=user)}")
                    found = True
                else:
                    print(f" {R}[NOT FOUND]{W} {site}")
            except:
                print(f" {R}[ERROR]{W} {site}")
        print()

    if not found:
        print(f"{Y}[!]{W} No public accounts found with these patterns")

def email_scan(email):
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        print(f"{R}[-] Invalid email format{W}")
        return

    print(f"\n{B}[+] EmailScan:{W} {email}")

    try:
        url = f"https://api.allorigins.win/raw?url=https://haveibeenpwned.com/unifiedsearch/{email}"
        r = requests.get(url, timeout=8)
        if "Breach" in r.text:
            print(f" {R}[ALERT]{W} Email found in data breach!")
        else:
            print(f" {G}[CLEAN]{W} No breach found in public DB")
    except Exception as e:
        print(f" {R}[ERROR]{W} Can't check breach: {e}")

    username = email.split('@')[0]
    sites = {
        "GitHub": f"https://github.com/{username}",
        "Twitter/X": f"https://x.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Facebook": f"https://facebook.com/{username}"
    }

    print(f" {Y}Checking username:{W} {username}")
    for site, url in sites.items():
        try:
            r = requests.get(url, timeout=4)
            if r.status_code == 200:
                print(f" {G}[FOUND]{W} {site}: {url}")
            else:
                print(f" {R}[NOT FOUND]{W} {site}")
        except:
            print(f" {R}[ERROR]{W} {site}")

def _convert_to_degrees(value):
    """Helper function to convert the GPS coordinates to degrees float"""
    try:
        d = float(value.values[0].num) / float(value.values[0].den)
        m = float(value.values[1].num) / float(value.values[1].den)
        s = float(value.values[2].num) / float(value.values[2].den)
        return d + (m / 60.0) + (s / 3600.0)
    except:
        return None

def meta_grab(filepath):
    path = Path(filepath)
    if not path.exists():
        print(f"{R}[-] File not found: {filepath}{W}")
        return

    print(f"\n{B}[+] MetaGrab:{W} {path.name}")

    # Analisis Nama File (Deteksi Sumber Sosmed)
    # Foto FB versi lama/baru seringkali memiliki pola angka panjang dipisahkan underscore, atau mengandung kata 'fb'
    fb_pattern = r'^\d+_\d+_\d+_[n|o]\.(jpg|jpeg)$|^fb_'
    if re.match(fb_pattern, path.name, re.IGNORECASE):
        print(f" {Y}Analisis Nama File{W}: {G}Terdeteksi sebagai format unduhan Facebook.{W}")
        print(f" {Y}Catatan{W}            : Meta secara otomatis menghapus koordinat GPS dan metadata asli dari gambar.")

    try:
        hash_md5 = hashlib.md5(path.read_bytes()).hexdigest()
        print(f" {Y}MD5 Hash{W}  : {hash_md5}")
        print(f" {Y}Size{W}      : {path.stat().st_size} bytes")
    except Exception as e:
        print(f" {R}Hash Error:{W} {e}")

    try:
        with open(path, 'rb') as f:
            tags = exifread.process_file(f, stop_tag='UNDEF')

        if not tags:
            print(f" {Y}EXIF{W}       : {R}No metadata found{W}")
        else:
            print(f" {Y}EXIF Data:{W}")
            for tag in ['Image Make', 'Image Model', 'EXIF DateTimeOriginal']:
                if tag in tags:
                    print(f"  {tag:22}: {tags[tag]}")
            
            # Ekstraksi dan pembuatan link Google Maps jika ada koordinat GPS
            if 'GPS GPSLatitude' in tags and 'GPS GPSLongitude' in tags:
                lat = _convert_to_degrees(tags['GPS GPSLatitude'])
                lon = _convert_to_degrees(tags['GPS GPSLongitude'])
                
                if lat and lon:
                    lat_ref = tags.get('GPS GPSLatitudeRef', 'N').values
                    lon_ref = tags.get('GPS GPSLongitudeRef', 'E').values
                    
                    if lat_ref == 'S': lat = -lat
                    if lon_ref == 'W': lon = -lon
                    
                    print(f"  {G}GPS Koordinat{W}        : {lat}, {lon}")
                    print(f"  {G}Google Maps Link{W}     : https://www.google.com/maps?q={lat},{lon}")
    except Exception as e:
        print(f" {R}EXIF Error:{W} {e}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="OSINT-Lite Tools by sdev",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python osint-lite.py --phone 08123456789
  python osint-lite.py --phone-social 08123456789
  python osint-lite.py --email test@gmail.com
  python osint-lite.py --meta photo.jpg
        """
    )

    parser.add_argument('--phone', help='Scan phone number basic info')
    parser.add_argument('--phone-social', help='Scan social accounts from phone number')
    parser.add_argument('--email', help='Scan email for breach & social accounts')
    parser.add_argument('--meta', help='Extract metadata from file')

    args = parser.parse_args()

    if args.phone:
        phone_intel(args.phone)
    elif args.phone_social:
        phone_social_scan(args.phone_social)
    elif args.email:
        email_scan(args.email)
    elif args.meta:
        meta_grab(args.meta)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
