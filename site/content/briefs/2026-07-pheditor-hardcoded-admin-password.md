---
title: Pheditor Hardcoded Admin Password Leads to Remote Code Execution (CVE-2026-55579)
slug: 2026-07-pheditor-hardcoded-admin-password
description: Pheditor contains a critical vulnerability (CVE-2026-55579) where a hardcoded default password 'admin' with no forced change mechanism upon first login allows an unauthenticated attacker to gain full administrative access, enabling arbitrary file read/write and remote code execution through the application's terminal feature, leading to complete server compromise.
date: "2026-07-16T20:13:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - hardcoded-credentials
  - rce
  - web-application
  - cve
vendors:
  - Pheditor
products:
  - Pheditor (All versions)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: ""
    evidence: Pheditor ships with a hardcoded default password `admin`... Any deployment using the default credentials grants an attacker full access...
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: exploit the terminal RCE... enabling arbitrary file read/write and remote code execution.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: 'Availability impact: High — delete files and directories, disrupt services.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-p4h7-p9rj-2pq2
---

Pheditor, a web-based file editor, is affected by a critical vulnerability, CVE-2026-55579, stemming from a hardcoded default password. The application ships with a default administrator password "admin," which is stored as an unsalted SHA-512 hash in the `pheditor.php` source file. There is no enforced mechanism to prompt a password change upon initial login, nor are there any lockout policies for incorrect attempts. This design flaw allows any unauthenticated attacker to bypass authentication by using the well-known default credentials. Upon successful login, the attacker gains full administrative control over the application's features, including file upload capabilities, arbitrary file read/write, and a terminal for remote code execution. This directly leads to server compromise, enabling data exfiltration, service disruption, and the establishment of persistent backdoors. All versions of Pheditor are affected.

## Attack Chain

1. An unauthenticated attacker identifies a Pheditor instance exposed to the internet.
2. The attacker attempts to authenticate to the Pheditor web interface using the publicly known default password "admin."
3. Pheditor accepts the default credentials, grants the attacker an authenticated session, and sets a session cookie.
4. The attacker loads the Pheditor interface, extracts the CSRF token from the HTML source, and gains full administrative control over the application's features.
5. Leveraging the authenticated session and CSRF token, the attacker accesses the built-in terminal feature.
6. The attacker executes arbitrary commands on the underlying server via the terminal, achieving remote code execution.
7. The attacker proceeds with further actions such as arbitrary file upload, reading sensitive files, modifying application code, or deleting directories, leading to full server compromise and data impact.

## Impact

The vulnerability (CVE-2026-55579, CWE-798) grants an unauthenticated attacker full administrator access to the Pheditor application if default credentials are in use. This leads to high impact across confidentiality, integrity, and availability. Attackers can read any files accessible by the web server process, potentially leading to sensitive data exposure. Integrity is compromised through the ability to write/delete files, upload webshells, or modify application code. Furthermore, the terminal feature allows for arbitrary command execution, providing complete control over the underlying server. This could lead to full system compromise, data exfiltration, defacement, or denial of service through deletion of critical files and directories.

## Recommendation

* **Immediately change the default 'admin' password** on all Pheditor instances to a strong, unique password.
* **Implement a robust password policy** that forces users to change default passwords upon first login.
* **Ensure Pheditor instances are not exposed to the public internet** unless absolutely necessary, and protect them behind a firewall or VPN.
* **Review web server access logs** for POST requests to `/pheditor.php` originating from unknown IP addresses, especially if `pheditor_password=admin` was used in the request body.
