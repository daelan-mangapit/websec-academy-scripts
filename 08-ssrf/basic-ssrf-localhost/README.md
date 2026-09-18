# Lab: Basic SSRF against the local server

- **Topic:** SSRF
- **Difficulty:** Apprentice
- **Lab:** https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost

## The vulnerability

The shop's stock checker takes a URL and the server fetches it to retrieve stock data. The catch is that you control that URL — it's the `stockApi` parameter in the request. So instead of the real stock API, you point it at `http://localhost/admin`, the site's own admin panel.

That admin panel is restricted to local access, meaning only the server itself can reach it. But the server is exactly what's making the request, so it fetches its own admin page and returns the HTML to you. Pointing the same parameter at `http://localhost/admin/delete?username=carlos` then makes the server carry out an admin action on your behalf.

## Why it matters

SSRF turns the server into a proxy into places an attacker can't reach directly. Internal services, admin panels, and cloud metadata endpoints are frequently protected only by network position — the assumption that a request could only come from a trusted internal source. The server sits in that trusted position, so any request an attacker can make it send inherits that trust, bypassing firewalls and access controls that would block the attacker directly.

That is especially dangerous in the cloud, and the canonical case is the 2019 Capital One breach. An SSRF flaw in a misconfigured web application firewall let the attacker make the server query the AWS instance metadata service — an internal-only endpoint that hands out temporary credentials. Those credentials had access to storage holding roughly 106 million credit card applications, including Social Security and bank account numbers. One SSRF, reaching one internal endpoint the attacker could not touch directly, escalated into one of the largest financial-data breaches on record — and AWS changed its metadata service industry-wide in response.

The root cause is fetching a user-controlled URL without restricting where it can point. The fix is to control the destination, not to trust the request's origin.

## How the script detects it

It sends the SSRF payload through the stock-check parameter, pointing it at the internal admin panel at `http://localhost/admin`. It confirms the attack worked by checking that the returned HTML is the admin page — it contains user-deletion links that only exist there. It then delivers the exploit by making the server fetch the delete URL, and verifies the target user is gone from the refreshed admin page rather than assuming the deletion succeeded.

## Remediation

Don't let user input decide which host the server contacts. Validate the destination against a strict allowlist of permitted URLs or hosts and reject anything else — allowlisting is far more reliable than blacklisting internal ranges, which attackers evade with alternative IP encodings and redirects. Enforce the check after resolving the hostname, so a name that resolves to an internal address is still blocked. As defense in depth, segment the network so internal services aren't reachable from the application server, and in cloud environments require the authenticated metadata service (such as AWS IMDSv2) so a bare SSRF can't retrieve credentials.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net