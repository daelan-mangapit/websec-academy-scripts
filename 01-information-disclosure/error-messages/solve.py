#!/usr/bin/env python3
# Lab: Information disclosure in error messages
# Link: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages

import re
import sys
import argparse
import requests

# Makes Python trust exactly what your operating system already trusts.
import truststore
truststore.inject_into_ssl()

# One reusable session; stores cookies automatically across requests.
session = requests.Session()

# Set from the command-line argument in main().
LAB_URL = None

# Common tech/version disclosure patterns seen in error pages.
VERSION_PATTERNS = [
    r"Apache Struts \d[\d.]*",
    r"Apache/\d[\d.]*",
    r"nginx/\d[\d.]*",
    r"PHP/\d[\d.]*",
    r"Werkzeug/\d[\d.]*",        # Flask's dev server
    r"Microsoft-IIS/\d[\d.]*",
]


def fetch(path, method="GET"):
    """Send a request to the lab and hand back the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url)


def report(name, found, detail=""):
    """Print a finding in a consistent format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def find_version_disclosure(text):
    """Return the first framework/version string found in text, or None."""
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return match.group()
    return None


def check_error_message_disclosure():
    resp = fetch("product?productId=UnExpectedInput")
    version = find_version_disclosure(resp.text)

    if version:
        report("Error-message disclosure", True, version)
    else:
        report("Error-message disclosure", False, "no version leaked")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect version disclosure in error messages (PortSwigger lab)."
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
        check_error_message_disclosure()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()