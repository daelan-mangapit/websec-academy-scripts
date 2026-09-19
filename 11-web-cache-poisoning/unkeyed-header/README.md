# Lab: Web cache poisoning with an unkeyed header

- **Topic:** Web Cache Poisoning
- **Difficulty:** Practitioner
- **Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header

## The vulnerability

The home page reflects the `X-Forwarded-Host` request header into an absolute URL used to import a JavaScript file — the response contains a `<script>` tag whose source is built from that header. The cache sitting in front of the application keys its stored responses on the URL but not on `X-Forwarded-Host`, so that header is unkeyed.

An attacker sends one request with a malicious `X-Forwarded-Host`, the server builds a page whose script loads from the attacker's domain, and the cache stores that poisoned page under the ordinary home-page URL. Every visitor served from the cache then loads the attacker's script — a single request poisons the page for everyone.

## Why it matters

Web cache poisoning weaponizes shared infrastructure. A cache exists to serve one stored response to many users, so poisoning it means a single malicious request affects everyone the cache serves. That is what makes it dangerous: a reflected input that would otherwise be self-inflicted — harming only the attacker who sends it — becomes a stored attack delivered to every visitor, with no action required on their part.

The impact depends on what the unkeyed input controls. Here it controls a script import, so the result is arbitrary JavaScript running in every visitor's browser — cookie theft, session hijacking, account takeover. Other unkeyed inputs have been used to force open redirects and serve malicious content. And the blast radius is the entire cache: potentially every user of the site until the entry expires or is purged.

The technique was defined by PortSwigger researcher James Kettle in his 2018 "Practical Web Cache Poisoning" research, which demonstrated it against real, high-profile sites. On Unity's website an unkeyed `X-Host` header controlled a script import — exactly the pattern in this lab — letting him serve arbitrary JavaScript to visitors straight from the cache, and he found similar issues on data.gov and other major properties. It showed that a header most developers never think about could turn a CDN into a malware distribution point.

The root cause is the cache and the application disagreeing about which inputs matter: the app uses `X-Forwarded-Host` to build the response, but the cache ignores it when deciding what counts as the same request. The fix is to make them agree.

## How the script detects it

It sends a request to the home page with a malicious `X-Forwarded-Host` header and a unique cache-buster, and confirms the value is reflected into the page's script import. It then sends a second request to the same URL with no header at all. If that clean request — one that never carried the malicious header — is served the poisoned response, and the `X-Cache` response header reports a cache hit, the cache has been poisoned. The script prints the cache status at each step so the miss-then-hit sequence is visible.

## Remediation

Either stop using the unkeyed header, or include it in the cache key. The cleanest fix is not to trust headers like `X-Forwarded-Host` when generating responses — use a configured, trusted host value instead of reflecting whatever the request supplies. If such a header genuinely must influence the response, the cache must key on it, so that a request with a different value gets a different cache entry rather than a shared one. More broadly, avoid caching responses that vary on inputs the cache doesn't account for, and be deliberate about exactly which inputs are keyed.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net

Fully solving the lab (executing `alert` in the victim's browser) requires
hosting the payload on the exploit server; the script confirms the poisoning.