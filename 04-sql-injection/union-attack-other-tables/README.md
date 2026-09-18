# Lab: SQL injection UNION attack, retrieving data from other tables

- **Topic:** SQL Injection
- **Difficulty:** Practitioner
- **Lab:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables

## The vulnerability

The product category filter builds its database query by dropping the `category` value straight into the SQL, with no sanitization. A request like `/filter?category=Gifts` runs a query along the lines of `SELECT ... FROM products WHERE category = 'Gifts'`.

Because the input lands inside that query, an attacker can break out of the string and add their own SQL. The technique here is a UNION attack. `UNION SELECT` appends the rows of a second query onto the first result set, so the app's query can be made to return data from a completely different table. This lab's query returns two text columns, which lines up with selecting `username` and `password` from the `users` table, so every credential comes back in the response.

## Why it matters

SQL injection is one of the most damaging web vulnerabilities, because the database usually holds the most sensitive data an application has. A single injectable parameter can expose the entire contents of the database — here, every user's credentials, including the administrator's, which is enough to take over the account.

It rarely stops at reading data. Depending on the database and its permissions, injection can also modify or delete records, bypass authentication, and in some cases run commands on the underlying server. The 2008 Heartland Payment Systems breach, which exposed around 130 million credit card numbers, began with SQL injection, and the technique still appears in breaches today. That is why it sits in the OWASP Top 10 as part of the Injection category.

The root cause is mixing untrusted input with query code. The database can't tell the attacker's SQL from the application's, so it runs both.

## How the script detects it

It sends a UNION payload through the injectable `category` parameter: `' UNION SELECT username, password FROM users--`. The single quote breaks out of the original string, the `UNION SELECT` appends the users table, and the trailing `--` comments out the rest of the original query. The payload is passed as a query parameter so it is URL-encoded correctly on the way out. The script then parses the response with a pattern that captures each username and password pair, and reports the full set of dumped credentials.

## Remediation

Never build SQL by concatenating user input into the query string. Use parameterized queries (prepared statements), where the input is passed separately from the query and always treated as data, never as executable SQL. This is the single most effective fix and closes the vulnerability regardless of what the input contains. As defense in depth, apply least-privilege database accounts so a compromised query can reach as little as possible, and validate input against expected formats, though input validation alone is not a reliable substitute for parameterized queries.

## Usage

    python3 solve.py https://YOUR-LAB-ID.web-security-academy.net