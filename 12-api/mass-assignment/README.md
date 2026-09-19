# Lab: Exploiting a mass assignment vulnerability

- **Topic:** API Testing
- **Difficulty:** Practitioner
- **Lab:** https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability

## The vulnerability

When you check out, the app sends a JSON order to `/api/checkout`. The framework binds every field in that JSON onto its internal order object, with no allowlist of which fields a user is allowed to set. That is mass assignment.

The `GET /api/checkout` response reveals a hidden `chosen_discount` field that the normal POST never sends — server-controlled in intent, but user-settable in practice. Add it to the POST with a percentage of 100, and the API applies a 100% discount, making the £1337 jacket free.

## Why it matters

Mass assignment lets an attacker set object properties they were never meant to control. The request looks completely legitimate — an authenticated user submitting a well-formed order — but it carries an extra field the application blindly writes to its object. Here that field is a discount, so the impact is financial: free goods. Applied to a field like `isAdmin`, `role`, `verified`, or `account_balance`, the same flaw becomes privilege escalation or account takeover, and it happens silently, with no error.

The danger is that these fields are invisible in the UI and absent from the normal request, yet present in the object model. Frameworks that auto-bind every request field for convenience — Rails, Django, Express, Spring, and others — expose them by default unless the developer explicitly restricts which fields are assignable. The tell, as this lab shows, is a response that returns more fields than the request sends.

The definitive example is the 2012 GitHub incident. Security researcher Egor Homakov exploited a mass assignment flaw in Ruby on Rails, the framework GitHub ran on, by adding a hidden `user_id` field to the SSH-key upload form. Because the code bound request parameters to the object with no allowlist, his key became associated with the official Rails account, granting him commit access to the Rails repository — which he proved by pushing a commit. GitHub patched it within an hour, and Rails made "strong parameters" the default protection soon after. It is the same move as this lab: smuggle in an extra field the framework binds to something you shouldn't control.

The root cause is binding user input to object fields without an allowlist. The fix is to allow only the fields the user is meant to set.

## How the script detects it

It logs in, adds the target item to the cart, and fetches `GET /api/checkout`, parsing the JSON response into an object. That response exposes the hidden `chosen_discount` field, which the normal checkout request never sends. The script sets that field's percentage to 100 and submits the whole object back to `POST /api/checkout` as JSON. It then checks the response for the absence of an insufficient-credit error, confirming the order went through and the item was bought for free.

## Remediation

Never bind request data directly to internal objects. Define an explicit allowlist of the fields a user is permitted to set — Rails calls this "strong parameters," and every major framework has an equivalent — and ignore anything else in the request. Sensitive properties like prices, discounts, roles, and account balances should be set and validated server-side, never taken from the request body. Reviewing what an API returns is worthwhile too, since fields exposed in responses are exactly the ones an attacker will try to set.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net