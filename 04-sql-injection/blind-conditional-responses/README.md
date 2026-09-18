# Lab: Blind SQL injection with conditional responses

- **Topic:** SQL Injection
- **Difficulty:** Practitioner
- **Lab:** https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses

## The vulnerability

The application puts the value of the `TrackingId` cookie into a SQL query. The query's results are never shown and error messages are suppressed, so an attacker can't read data directly or use a UNION attack. But the page includes a "Welcome back" message whenever the query returns a row.

That single difference — message present or absent — is a boolean oracle. By injecting a condition into the cookie and watching whether "Welcome back" comes back, an attacker learns whether that condition was true, and can infer the database's contents one true-or-false answer at a time. It's called "blind" because the database never returns data directly; you deduce it.

## Why it matters

This has the same root cause as any SQL injection — untrusted input mixed into a query — but it makes a point that catches teams out: hiding the query's output is not a fix. Developers sometimes assume that if results and errors aren't displayed, injection can't be exploited. Blind injection disproves that. Any observable difference in the response — a message like this one, a changed status code, even how long the response takes — is enough to leak the whole database, just more slowly.

The end impact is identical to visible SQL injection: complete extraction of sensitive data, here the administrator's password. The only cost to the attacker is more requests, which is trivially automated — this exact technique is what tools like sqlmap perform at scale. So "we don't return the data" buys nothing. The fix has to be at the query, not the display.

## How the script detects it

It builds a boolean oracle: a function that injects a condition into the `TrackingId` cookie and returns whether the "Welcome back" marker appears, meaning the condition was true. Using that oracle, it works in two phases. First it finds the password length by asking whether `LENGTH(password)` is greater than a steadily increasing number, until the answer flips to false. Then it recovers each character by asking, at every position, whether `SUBSTRING(password, position, 1)` equals each candidate character until one matches. The answers assemble into the full password.

## Remediation

Use parameterized queries (prepared statements), so input is always handled as data and never as SQL. This is the real fix, and it closes blind and visible injection alike. Note what does *not* work: suppressing error messages and hiding query results is not a defense, because a boolean or timing side channel still leaks the data. Defense in depth — least-privilege database accounts, input validation — limits the damage but does not replace parameterized queries.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net

Extraction runs many requests and takes a couple of minutes; progress prints
as the password is recovered.