# Lab: Authentication bypass via OAuth implicit flow

- **Topic:** OAuth Authentication
- **Difficulty:** Apprentice
- **Lab:** https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow

## The vulnerability

The blog lets users log in with a social account using OAuth's implicit flow. In that flow, the OAuth provider returns the access token to the user's browser, and the browser then POSTs the user's profile — email, username — plus the token to the blog's own `/authenticate` endpoint to establish a session.

The flaw is in that final request. `/authenticate` checks that the token is genuine, but it never checks that the submitted email actually belongs to that token. So an attacker completes the flow with their own account to obtain a valid token, then re-sends the `/authenticate` request with the victim's email instead. The server binds the session to the email, logging the attacker in as the victim — with a valid token, but the wrong identity attached to it, and no password required.

## Why it matters

This is complete authentication bypass: logging into any user's account without their password, knowing only their email address, which is often public. There is no credential theft and no phishing — the attacker uses their own legitimate login and simply relabels it as someone else.

Two failures combine to make it possible. The implicit flow routes the access token and profile through the browser, where the user controls everything in transit — which is exactly why the flow is now discouraged and removed in OAuth 2.1. And the client trusts the email as identity without binding it to the one thing that was actually verified: the token.

That precise class of flaw hit Apple at scale. In 2020, researcher Bhavuk Jain found that Sign in with Apple — Apple's OAuth-based single sign-on — would issue a validly signed token for any email an attacker requested, without confirming they owned it. Because the token verified correctly against Apple's public key, any third-party app trusting it could be taken over: full account takeover of any user, knowing only their email, across services like Dropbox, Spotify, and Airbnb that used the feature. Apple paid a $100,000 bounty. The failure was the same one as this lab — an identity not bound to the verified token.

The root cause is trusting a user-supplied identity that isn't tied to what was actually authenticated. The fix is to bind them.

## How the script detects it

It runs the full OAuth flow as its own user (wiener) — following the redirect chain across the blog and the OAuth server, logging in, granting consent, and extracting the access token that the implicit flow returns in a URL fragment. With that valid token, it sends the client's `/authenticate` request but substitutes the victim's email, then fetches the account page to confirm it now belongs to the victim rather than assuming the attack worked.

## Remediation

Bind the identity to the verified token. The client must not trust profile data such as the email sent alongside the token; it should derive the user's identity from the token itself — for OpenID Connect, from the verified claims inside the ID token, or by calling the provider's userinfo endpoint with the token and using what that returns. More fundamentally, avoid the implicit flow entirely and use the authorization code flow, where the token is exchanged server-to-server and never exposed to the browser for tampering. OAuth 2.1 removes the implicit flow for exactly this reason.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net