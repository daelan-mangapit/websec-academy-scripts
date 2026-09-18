# Lab: Insecure direct object references

- **Topic:** Access Control
- **Difficulty:** Apprentice
- **Lab:** https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references

## The vulnerability

The site's live chat lets you download your conversation transcript, served from `/download-transcript/2.txt` — a static file named with an incrementing number. Those files have no access control. Nothing checks that the transcript you request is actually yours.

So changing `2.txt` to `1.txt` returns a different user's chat. That transcript belongs to carlos, and in the conversation he states his password out loud, which is enough to log into his account.

## Why it matters

This is an insecure direct object reference (IDOR). The application points at a resource — the transcript file — using an identifier the user can see and change, without checking whether that user is allowed to access it. Change the reference, read someone else's data. It's a form of broken access control, which OWASP currently ranks number one in its Top 10, and IDOR is one of its most common shapes.

The impact scales frighteningly, because the flaw is trivial to automate — you just loop the numbers. The 2019 First American Financial breach is the textbook case, and it mirrors this lab almost exactly. Roughly 885 million sensitive documents, including mortgage records, bank account numbers, and Social Security numbers, were exposed because each was reachable at a sequential URL with no authentication. Anyone could read another person's document by changing a single digit — no hacking tools, no stolen credentials, the same move this script makes.

The root cause is trusting a client-controlled reference for authorization. The fix is to check, on every request, that the current user is allowed to access the specific object being requested.

## How the script detects it

It enumerates the transcript files by requesting `/download-transcript/1.txt`, `2.txt`, and so on up to a limit, and harvests every one that returns successfully — data it should not be able to reach. It prints each transcript it recovers, and because carlos's chat states his password in plain text, it also extracts that password with a pattern anchored on the phrase where it appears.

## Remediation

Enforce access control on every request for a resource. Check that the authenticated user actually owns, or is permitted to see, the specific object requested — never assume that holding a valid reference means being authorized to use it. Don't rely on identifiers being hard to guess, either; that's security through obscurity, and even unpredictable IDs need a real authorization check behind them. For files specifically, avoid serving user data as static files at predictable paths — serve them through a handler that verifies ownership first.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net