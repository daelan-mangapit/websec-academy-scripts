# Lab: Remote code execution via web shell upload

- **Topic:** File Upload
- **Difficulty:** Apprentice
- **Lab:** https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload

## The vulnerability

The avatar upload accepts any file without checking that it's actually an image, and stores it in a directory where the server executes code. So instead of an image, an attacker uploads a PHP script — a web shell.

Uploading the file does nothing on its own. But requesting it at its URL makes the server execute it. This shell reads `/home/carlos/secret` and returns it, but the same technique runs any code the attacker chooses. Two things had to line up: the upload didn't validate what it accepted, and the upload location runs code.

## Why it matters

Uploading a web shell is remote code execution — the most severe outcome a web vulnerability can have. The attacker isn't reading one file or one database; they're running arbitrary code on the server. That means full compromise: read and write any file, run system commands, install malware, and pivot into the internal network.

Because two conditions have to combine — no validation of the upload, and a location that executes it — the fix has to address both, since either alone can fail.

Web shells are not a lab curiosity; they are one of the most common tools in real intrusions, so much so that CISA defines a web shell plainly as a script uploaded to a compromised server to enable remote administration of it. They were central to the 2021 Microsoft Exchange attacks, where Hafnium and other groups exploited server flaws and then dropped web shells to keep persistent, SYSTEM-level control — running commands even after the original vulnerabilities were patched. Around 60,000 organizations worldwide were affected. The web shell is exactly the artifact this lab has you upload, and in that campaign it was the mechanism behind one of the largest intrusions of the year.

The root cause is trusting an uploaded file — both its contents and where it is allowed to run. The fix is to trust neither.

## How the script detects it

It logs in, retrieves the upload form's CSRF token, and uploads a small PHP web shell through the avatar function as a multipart form submission. It then makes a second request to the uploaded file's URL, which causes the server to execute the script and return the contents of `/home/carlos/secret` in the response. The script extracts and reports that secret, confirming code execution on the server.

## Remediation

Validate uploads and prevent the upload directory from executing code — both, since either defense alone can be bypassed. Check the file's actual type rather than trusting its extension or Content-Type, and store uploads outside the web root or somewhere configured never to run scripts. Rename uploaded files to values the user doesn't control, so their path can't be predicted or manipulated, and serve them through a handler rather than as directly executable files. Defense in depth matters here precisely because a file-upload flaw leads straight to remote code execution, the worst-case outcome.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net