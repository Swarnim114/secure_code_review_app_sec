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

