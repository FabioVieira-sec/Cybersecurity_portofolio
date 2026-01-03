# 🔓 Broken Access Control: Methodology & Practice

Broken Access Control is currently the **#1 risk in the OWASP Top 10**. It occurs when an application fails to properly enforce permissions, allowing users to access data or functions outside their intended path.



---

## 🛠️ My Testing Checklist

When auditing an application for Access Control flaws, I always look for these three main vectors:

### 1. Insecure Direct Object References (IDOR)
This happens when the app uses user-supplied input to access objects directly. 
* **The Test:** I identify parameters like `?id=123` or `?user=fvieira` and attempt to swap them for other valid identifiers.
* **Practical Example:** In a recent lab environment, I bypassed the "unpredictable ID" security by finding a password disclosure flaw in the user profile page, which allowed me to leak credentials of other users by simply iterating through IDs.
* **Tooling:** Burp Suite Repeater & Intruder.

### 2. Parameter Tampering (Privilege Escalation)
Some applications trust the client to tell them what their "role" is. 
* **The Test:** I look for hidden fields or parameters such as `admin=false`, `roleid=1`, or `is_admin=no` in cookies or POST bodies.
* **Practical Example:** I successfully escalated privileges from a standard user to an administrator by modifying the `admin` parameter from `false` to `true` during the account update request.
* **Remediation:** Roles must be assigned and verified server-side via session tokens, never by client-side parameters.

### 3. Vertical vs. Horizontal Escalation
I categorize my findings into two types:
* **Horizontal:** Accessing data of a user at the same level (e.g., User A seeing User B's private messages).
* **Vertical:** Accessing functions of a higher-level user (e.g., a Customer accessing the Admin Dashboard via `/admin` or `/unprotected-panel`).

---

## 🧪 Featured Labs (PortSwigger)

While I have completed the full Access Control module, these labs highlight the core concepts:

* **Lab: Unprotected admin functionality:** Demonstrated how security through obscurity (hidden URLs) is not a substitute for proper access control.
* **Lab: User ID controlled by request parameter:** Successfully performed a horizontal escalation to view sensitive account details.
* **Lab: Parameter-based access control:** Exploited a flawed implementation where the user role was stored in a modifiable cookie.

---

## 🛡️ Best Practices for Remediation
1.  **Deny by Default:** If a resource isn't explicitly public, it should require authentication and authorization.
2.  **Centralize Control:** Permissions should be handled by a single, well-audited library or middleware.
3.  **Disable Web Server Directory Listing:** Prevent attackers from discovering sensitive files or backup folders.
