# Lab: Exploiting XXE using external entities to retrieve files

- **Topic:** XXE Injection
- **Difficulty:** Apprentice
- **Lab:** https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files

## The vulnerability

The stock checker doesn't take form fields — it takes an XML document, and the server parses it. XML supports a feature called external entities: a document can define a named entity whose value is loaded from a URI, and that URI can be a local file path. This parser resolves those entities, which is the flaw.

So the attacker defines an entity whose value is the contents of `/etc/passwd`, then references that entity where the product ID normally goes. When the parser expands the reference, it reads the file and substitutes its contents, and the app hands them back inside its "Invalid product ID:" error message. The attacker asked a stock checker for a product and got a system file instead.

## Why it matters

XXE lets an attacker make the server read files it should never expose — source code, configuration files with credentials, SSH keys, `/etc/passwd`. And file read is only the first of its capabilities. Because an external entity can point at a URL instead of a file, XXE also enables SSRF, reaching internal services and cloud metadata endpoints. Blind variants can exfiltrate data out-of-band even when nothing is reflected, and a malicious entity can crash the parser outright.

The severity is real, not theoretical. In 2014, researcher Reginaldo Silva found an XXE flaw in the code that handled OpenID logins on Facebook's servers. It read the server's `/etc/passwd` file — the same file this lab targets — and Facebook confirmed it could be escalated to remote code execution, awarding what was then its largest-ever bug bounty at $33,500. A "read a file" bug on a major platform turned out to be a path to running code on their servers.

The root cause is an XML parser that resolves external entities, processing untrusted XML with that feature left enabled. The fix is to turn it off.

## How the script detects it

It sends a series of crafted XML documents to the stock checker, each defining an external entity aimed at a different resource — the Unix password file, a Windows configuration file, a PHP filter wrapper that base64-encodes source code, and the cloud metadata endpoint (which turns the XXE into an SSRF). Each document references its entity where the product ID normally goes. For every payload the script checks the response for that payload's success marker, and on a hit it extracts and prints the leaked data and reports which payload worked. Against this lab the Unix file-read payload succeeds and returns `/etc/passwd`; the others document the wider technique.

## Remediation

Disable external entity and DTD processing in the XML parser — this is the single, complete fix, and virtually every XML library provides a flag or a secure-processing mode for it. Since almost no application that accepts XML actually needs to resolve external entities, turning the feature off breaks nothing legitimate while closing XXE entirely. Prefer parser configurations that are secure by default, and keep XML libraries patched.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net