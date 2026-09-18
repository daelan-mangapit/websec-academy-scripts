# Lab: JWT authentication bypass via weak signing key

- **Topic:** JWT
- **Difficulty:** Practitioner
- **Lab:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key

## The vulnerability

Your session is a JWT — a token carrying your identity (`sub: wiener`) plus a signature proving the server issued it. The payload isn't encrypted, so anyone can read and change it. The signature is the only thing stopping forgery: it's an HMAC-SHA256 of the token's header and payload, keyed with a secret the server holds.

Here that secret is weak — a common value (`secret1`) that appears in public wordlists. So an attacker can brute-force it, then sign their own token claiming to be the administrator, and the server accepts it as genuine.

## Why it matters

A JWT is only as trustworthy as its signing key. Because the payload is readable and editable, the signature is the entire security boundary, and a weak HMAC secret erases it. An attacker who recovers the secret can mint a valid token for any user. That's complete authentication bypass: log in as anyone, escalate to administrator, take over accounts.

What makes it worse is that cracking the secret is an offline attack. The attacker already holds a signature, so they test candidate keys locally, computing the HMAC themselves and comparing. No requests hit the server, so rate limiting, lockouts, and monitoring are all irrelevant — a weak secret falls in seconds against a wordlist, exactly as this script does.

This is a common real-world failure, not a contrived one. Weak or default signing secrets — values like "secret" or a framework's example key left in production — are among the most frequent JWT findings in real assessments, which is exactly why curated wordlists of common JWT secrets exist. It's a cryptographic failure (a weak key) enabling an authentication failure (a forged identity), two of the most serious categories in the OWASP Top 10.

The root cause is a guessable signing secret. The fix is a strong one.

## How the script detects it

It logs in as a normal user to obtain a genuine JWT, then brute-forces the signing secret entirely offline. For each candidate in a wordlist, it re-computes the HMAC-SHA256 signature over the token's own header and payload and compares it to the token's actual signature; a match reveals the secret. With the secret known, it forges a new token — decoding the payload, changing the `sub` claim to `administrator`, and re-signing with the cracked key — then sends that token to the admin panel to confirm the forged identity is accepted.

## Remediation

Sign JWTs with a strong, high-entropy secret — a long random value, never a word, phrase, or framework default — so it can't be brute-forced. Store it securely outside source code, and rotate it periodically. For HMAC-signed tokens (HS256), key strength is the whole defense, so treat the secret like any other critical credential. Higher-assurance applications often prefer asymmetric signing (RS256/ES256), where the server signs with a private key and only the public key is exposed, removing the shared-secret brute-force risk entirely.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net

Requires the common-JWT-secrets wordlist saved as `secrets.txt` in the same
folder; run from inside that folder.