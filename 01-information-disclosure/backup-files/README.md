# Lab: Source code disclosure via backup files

- **Topic:** Information Disclosure
- **Difficulty:** Apprentice
- **Lab:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files

## The vulnerability

The site leaves a backup copy of a source file — `ProductTemplate.java.bak` — sitting in a web-accessible `/backup` directory. That `.bak` holds the application's Java source, and the source has a database password hard-coded into the connection setup. The directory isn't really hidden, either. `robots.txt` lists `/backup` under `Disallow`, which is meant to keep search crawlers out but instead advertises the folder to anyone who reads the file.

## Why it matters

Two problems stack here. First is source code disclosure: an attacker who can read your code sees its logic, its structure, and its other weak points, which makes every later attack easier. Second, and worse, the code contains a live secret — a database password in plain text. That's direct access to the database, no exploit required.

Hard-coding credentials into source is the exact mistake behind the 2016 Uber breach. Attackers found AWS keys hard-coded in a private GitHub repository, used them to reach an S3 datastore, and took data on 57 million users and drivers. So a password left in a file isn't a minor slip. It's a straight line to full data compromise, and a leftover `.bak` on a public server is just an easier version of the same exposure.

## How the script detects it

It follows the disclosure chain automatically. First it reads `/robots.txt` and pulls out the disallowed path. Then it requests that directory and finds the `.bak` filename in the listing. Finally it fetches the `.bak` source and extracts the hard-coded password with a pattern that matches the connection setup. Each step guards its result, so a broken link in the chain reports cleanly instead of crashing.

## Remediation

Keep backup files out of the web root entirely, and disable directory listing so a folder can't be browsed. More importantly, don't hard-code credentials in source code at all. Load them from environment variables or a secrets manager at runtime, and rotate any secret that has already been committed to a file or repository. And don't lean on `robots.txt` to hide anything — it's a crawler hint, not access control, and it often just points attackers straight at what you wanted hidden.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net