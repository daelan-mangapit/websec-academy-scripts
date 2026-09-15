# Lab: Information disclosure in error messages

**Topic:** Information Disclosure
**Difficulty:** Apprentice
**Lab:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages

## The vulnerability
The product page loads details from a `productId` query parameter that the
server treats as an integer. Supplying a non-integer value triggers an
unhandled exception, and instead of a generic error page the application
returns a full stack trace naming the backend framework and its exact
version — here, Apache Struts 2 2.3.31.

## Why it matters
A leaked version string turns a "harmless" error into a targeted attack.
Apache Struts 2 2.3.31 falls in the range affected by CVE-2017-5638, a
critical (CVSS 10.0) unauthenticated remote-code-execution flaw in the
Jakarta Multipart parser: an attacker runs arbitrary OS commands by sending
a crafted `Content-Type` header, with no login required. It's the same flaw
behind the 2017 Equifax breach. So the disclosure isn't the whole attack —
it's the reconnaissance step that tells an attacker exactly which public
exploit to point at the server.

## How the script detects it
It requests `/product` with a deliberately non-integer `productId` to force
the error, then searches the response body against a list of known
framework/version regex patterns (Struts, Apache, nginx, PHP, and so on). If
one matches, it reports the disclosed version; otherwise it reports clean.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net

## Remediation
Return generic, non-descriptive error pages to users and disable verbose
stack traces / debug mode in production — log the detail server-side where
users can't see it. And keep the framework patched: the disclosed version
being exploitable at all is the deeper problem the leak exposes.