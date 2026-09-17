# Lab: Username enumeration via different responses

- **Topic:** Authentication
- **Difficulty:** Apprentice
- **Lab:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses

## The vulnerability

The login form gives away too much. When a login fails, it tells you *which* field was wrong. A username that doesn't exist returns "Invalid username", while a real username with the wrong password returns "Incorrect password".

That difference is the leak. An attacker can discover valid usernames just by watching which message comes back, without knowing a single password. Once a valid username is confirmed, its password can be brute-forced from a wordlist. A successful login is signalled by a 302 redirect to the account page.

## Why it matters

This is username enumeration, and it turns a login form into an oracle for valid accounts. An attacker builds a list of real usernames with no credentials at all, and that list is the setup for everything that follows.

The obvious next step is what this lab does: brute-force the password of a known-good account. But it also feeds credential stuffing — automated login attempts using credentials stolen from other breaches — which is one of the most common attacks on web logins. A confirmed list of valid usernames makes that far more efficient, and pairs dangerously with a breach password dump. The same leak also sharpens phishing, since the attacker now knows exactly who has an account.

The root cause is the app being specific about *why* a login failed. That's why modern login forms return a single generic "Invalid username or password" for every failure.

## How the script detects it

It runs the attack in two phases. First it POSTs each candidate username to `/login` with a dummy password and watches for the "Incorrect password" message, which only appears for a username the app recognizes. That reveals the valid account. Then it POSTs that username with each candidate password and watches for a 302 redirect, which signals a successful login. It reads both wordlists from local files and reports the recovered credentials.

## Remediation

Return a single, identical error message for every failed login — something like "Invalid username or password" — so the response never reveals which field was wrong. Make sure the responses are genuinely identical: same wording, same status code, same timing, since even subtle differences leak the same information. Beyond the message, add brute-force defenses — rate limiting, throttling or lockout after repeated failures, and CAPTCHA or multi-factor authentication to blunt automated guessing even when a username is known.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net

Requires the lab's candidate `usernames.txt` and `passwords.txt` wordlists
in the same folder; run from inside that folder.