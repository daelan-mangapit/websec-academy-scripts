# Lab: Blind OS command injection with time delays

- **Topic:** OS Command Injection
- **Difficulty:** Practitioner
- **Lab:** https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays

## The vulnerability

The feedback form passes user input into a shell command on the server. Shells treat characters like `;`, `&`, `&&`, `||`, `|`, backticks, and `$(...)` as command separators or substitutions, so unsanitized input can terminate the intended command and run the attacker's own instead. Here the `email` field is the injectable one.

The command's output is never shown in the response, which makes this "blind." You can't read the result off the page, so injection is confirmed a different way: by making the command take a measurable amount of time. A payload that pauses for about ten seconds, and a response that arrives ten seconds late, proves the command ran.

## Why it matters

OS command injection is among the most severe web vulnerabilities, because it hands the attacker code execution on the server itself. Where SQL injection reaches the database, command injection reaches the operating system — arbitrary commands running with the web server's privileges. That typically means full server compromise: reading and writing files, installing malware, stealing secrets, and pivoting deeper into the internal network.

Being blind does not reduce the severity; it only changes how the attacker detects it. Once a command runs, they can escalate to a reverse shell or exfiltrate data out-of-band, whether or not the output is visible in the response.

The canonical example is Shellshock (CVE-2014-6271), a 2014 flaw in the Bash shell classified as OS command injection (CWE-78). It let attacker-controlled input — often an HTTP header reaching a CGI script that invoked Bash — execute arbitrary commands as the web server's user. Rated maximum severity, it was exploited within hours of disclosure to build botnets, and it is still scanned for today. It is the clearest demonstration of why untrusted input reaching a shell is a full-compromise risk, not a minor one.

The root cause is passing user input to a shell at all. The fix is to avoid the shell.

## How the script detects it

Because the command's output isn't returned, the script proves execution by timing. It first measures a baseline — how long a normal feedback submission takes. Then it submits a series of payloads that use different shell separators and command-substitution forms to run a command that pauses for roughly ten seconds. If any payload makes the response arrive more than a few seconds slower than the baseline, that delay confirms the injected command executed. The script fetches a fresh CSRF token before each submission and stops at the first payload that works.

## Remediation

The most effective fix is to never invoke a shell with user input. Use language APIs that perform the task directly instead of shelling out. If a system command genuinely must be run, use a parameterized API that passes arguments as a separate list rather than a single string the shell parses, so user input can't be interpreted as commands or separators. Validating input against a strict allowlist is a useful additional layer, but on its own it is not a reliable defense.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net