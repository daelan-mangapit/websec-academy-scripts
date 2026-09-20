# Web Security Academy — Solver Scripts

Python scripts that solve [PortSwigger Web Security Academy](https://portswigger.net/web-security) labs, one per vulnerability class. Each script automates the detection and exploitation of a specific web vulnerability against its lab, and ships with a writeup covering the flaw, its real-world impact, and how to fix it.

## Why this exists

This project proceeds from a straightforward premise: security concepts are internalized most effectively through implementation rather than interaction. Completing a laboratory exercise by hand in Burp Suite demonstrates a procedure; reconstructing that solution as a script requires comprehending the underlying vulnerability in sufficient depth to express it programmatically — its mechanism, its boundary conditions, and the reasoning behind an effective remediation.

The intent is not to contribute novel tooling; equivalent detection logic is already well established in mature scanners. The intent is to evidence comprehension. Each script constitutes a demonstration that the corresponding vulnerability class is understood from first principles, while the collection as a whole functions as a compact, reusable web-assessment toolkit. Every script was authored and debugged from scratch, and I can account for its logic in full.

## How it's organized

Labs are grouped by topic, then by individual lab. Each lab folder holds a `solve.py` and its own `README.md` documenting that specific vulnerability:

    websec-academy-scripts/
    ├── README.md
    ├── 01-information-disclosure/
    │   ├── error-messages/
    │   │   ├── solve.py
    │   │   └── README.md
    │   └── backup-files/
    │       ├── solve.py
    │       └── README.md
    └── 04-sql-injection/
        ├── union-attack-other-tables/
        │   ├── solve.py
        │   └── README.md
        └── blind-conditional-responses/
            ├── solve.py
            └── README.md

Each lab README follows the same structure: what the vulnerability is, why it matters (with a real-world breach that used it), how the script detects it, and how to remediate it.

## Labs

15 labs across 13 vulnerability classes, from apprentice to practitioner:

| # | Topic | Lab | Difficulty |
|---|-------|-----|------------|
| 01 | Information Disclosure | [Error-message version disclosure](01-information-disclosure/error-messages/) | Apprentice |
|    |                        | [Source code disclosure via backup files](01-information-disclosure/backup-files/) | Apprentice |
| 02 | Path Traversal | [File path traversal, simple case](02-path-traversal/file-path-traversal-simple/) | Apprentice |
| 03 | Authentication | [Username enumeration via different responses](03-authentication/username-enumeration-different-responses/) | Apprentice |
| 04 | SQL Injection | [UNION attack, retrieving data from other tables](04-sql-injection/union-attack-other-tables/) | Practitioner |
|    |               | [Blind SQL injection with conditional responses](04-sql-injection/blind-conditional-responses/) | Practitioner |
| 05 | Access Control | [Insecure direct object references (IDOR)](05-access-control/insecure-direct-object-references/) | Apprentice |
| 06 | OS Command Injection | [Blind OS command injection with time delays](06-os-command-injection/blind-time-delays/) | Practitioner |
| 07 | JWT | [Authentication bypass via weak signing key](07-jwt/weak-signing-key/) | Practitioner |
| 08 | SSRF | [Basic SSRF against the local server](08-ssrf/basic-ssrf-localhost/) | Apprentice |
| 09 | XXE Injection | [XXE external-entity file retrieval](09-xxe/retrieve-files/) | Apprentice |
| 10 | File Upload | [Remote code execution via web shell upload](10-file-upload/web-shell-upload/) | Apprentice |
| 11 | Web Cache Poisoning | [Web cache poisoning with an unkeyed header](11-web-cache-poisoning/unkeyed-header/) | Practitioner |
| 12 | API Testing | [Exploiting a mass assignment vulnerability](12-api/mass-assignment/) | Practitioner |
| 13 | OAuth | [Authentication bypass via OAuth implicit flow](13-oauth/auth-bypass-implicit-flow/) | Apprentice |

Techniques span passive recon, payload fuzzing, offline credential cracking, timing-based blind inference, token forgery with hand-rolled HMAC, and multi-host authentication-flow abuse.

## Usage

Each PortSwigger lab spins up its own unique hostname, so you pass the lab URL as an argument:

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net

Requirements:

    pip install requests truststore

(`truststore` makes Python verify TLS against the OS trust store — useful on networks that inspect HTTPS.) A few labs also need their provided wordlists placed in the lab folder; that's noted in each lab's own README.

## Scope & responsible use

Every script here targets **PortSwigger's Web Security Academy**, a sanctioned, intentionally vulnerable training environment. These tools are for that authorized lab context and for learning only — do not run them against any system you do not have explicit permission to test.
