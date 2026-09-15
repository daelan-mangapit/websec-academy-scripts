# Lab: File path traversal, simple case

- **Topic:** Path Traversal
- **Difficulty:** Apprentice
- **Lab:** https://portswigger.net/web-security/file-path-traversal/lab-simple

## The vulnerability

The shop serves product images through `GET /image?filename=<name>`, reading the named file off disk to return it. The filename is used without validation. So instead of an image name, you can supply a traversal sequence like `../../../etc/passwd`. Each `../` climbs up one directory, so this walks out of the image folder to the filesystem root and into `/etc/passwd`. The response comes back with the file's contents in place of an image.

## Why it matters

Path traversal (CWE-22, "dot-dot-slash") lets an attacker read files outside the web root. That includes application source code, config files holding database credentials or API keys, SSH keys, and `/etc/passwd`. On its own, that's already a serious leak.

It also tends to escalate. The same class of flaw behind CVE-2021-41773 in Apache HTTP Server 2.4.49 went from arbitrary file read to unauthenticated remote code execution where CGI was enabled, and it was exploited in the wild. So reading a file is usually just the first step toward full server compromise. That's why an image loader that trusts a filename is a real finding, not a curiosity.

## How the script detects it

It requests the image endpoint with a traversal payload as the filename. Then it checks whether the response body contains `root:`, the first field of every `/etc/passwd` entry. If that string is present, a real file was read rather than an error page returned. The payloads live in a list, and the loop returns on the first one that works. The list also carries bypass techniques for the harder labs in this topic (absolute path, non-recursive stripping, and so on), ready for when you build those.

## Remediation

The best fix is to not pass user input to filesystem calls at all. Serve images by an ID that maps to a known filename on the server side. If a filename must be accepted, validate it against an allowlist, then resolve the full path and confirm it still sits inside the intended directory before reading. And reject traversal sequences outright rather than trying to strip them, since naive stripping is exactly what the harder labs bypass.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net