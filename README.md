# Secure Code Review Report
## Scaler Support Desk Assignment

### Student Information

| Field                     | Details              |
|---------------------------|----------------------|
| Student Name              | Swarnim              |
| Roll Number               | 23bcs10139           |
| Batch / Section           | 2027 |
| Email ID                  | swarnim.23bcs10139@sst.scaler.com    |
| Static Analysis Tool Used | Semgrep              |

---

## Findings Summary

During the secure code review of the Scaler Support Desk application, an extensive analysis was conducted using both automated SAST tools (Semgrep) and deep manual code inspection. A total of 20 findings have been documented.

**True Positives:**
1. SQL Injection
2. OS Command Injection
3. Remote Code Execution (Eval Injection)
4. Path Traversal (Insecure File Download)
5. Insecure Password Hashing (MD5)
6. Stored Cross-Site Scripting (XSS)
7. Broken Access Control (Admin Bypass)
8. Insecure Direct Object Reference (IDOR) - Viewing Tickets
9. Business Logic Flaw (Negative Escalation Cost)
10. Race Condition (TOCTOU in Escalation)
11. Hardcoded Backdoor / Auth Bypass
12. Unrestricted File Upload
13. Security Misconfiguration (Hardcoded Secret Key)
14. Security Misconfiguration (Debug Mode Enabled)
15. Cross-Site Request Forgery (CSRF)
16. In-Memory File Processing Denial of Service (DoS)
17. Missing Rate Limiting (Brute Force)
18. IDOR - Uploading Attachments to Other Tickets

**False Positives:**
19. SQL Injection (in `tickets_by_status`)
20. OS Command Injection (in `ping_internal`)

---

## Detailed Findings

---

### Finding 1

**1. Vulnerability Title:**
SQL Injection

**2. Classification:**
- **True Positive**
- False Positive

**Justification:**
The `term` parameter from user input is directly concatenated into the SQL query string without sanitization or parameterization, allowing an attacker to manipulate the query.

**3. Source File Information:**

| Field                      | Details                          |
|----------------------------|----------------------------------|
| File Name                  | `supportdesk-app/models.py`      |
| Function Name              | `search_tickets`                 |
| Vulnerable Line Number(s)  | 117–118                          |

| Field               | Details                                                   |
|---------------------|-----------------------------------------------------------|
| CWE       | CWE-89 — https://cwe.mitre.org/data/definitions/89.html   |
| Severity  | Critical                                                  |

**4. Screenshot of SAST Tool Output:**
![Semgrep — SQL Injection models.py line 118](screenshot/f1_sast.png)
> Semgrep Rule: `python.sqlalchemy.security.sqlalchemy-execute-raw-query` — Line 118

**5. Screenshot of Vulnerable Code:**
![Vulnerable code — search_tickets() models.py lines 115-120](screenshot/f1_code.png)
> File: `supportdesk-app/models.py` — Lines 115–120

**6. Why is it Vulnerable?**
- **Why the code is vulnerable:** Line 117 builds the SQL query by directly concatenating user input: `sql = "SELECT * FROM tickets WHERE subject LIKE '%" + term + "%'"`. There is no use of parameterized queries or any sanitization.
- **How the vulnerability could be exploited:** An attacker can send a payload like `%' UNION SELECT id, username, password_hash, role, escalation_credits FROM users --` to dump the entire users table, including password hashes.
- **What makes it a True Positive:** User input from `request.args.get("q")` flows directly into `models.search_tickets(term)` which places it verbatim into the SQL string. Semgrep confirmed this at line 118.

**7. Security Impact:**
Confidentiality breach (information disclosure of all user data), potential Authentication Bypass, and full database compromise.

**8. Recommended Remediation:**
Replace string concatenation with a parameterized query:
```python
sql = "SELECT * FROM tickets WHERE subject LIKE ?"
rows = conn.execute(sql, ('%' + term + '%',)).fetchall()
```

**References:**
- OWASP: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

---

