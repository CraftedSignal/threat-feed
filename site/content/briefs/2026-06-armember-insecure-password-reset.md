---
title: ARMember Premium Plugin Insecure Password Reset (CVE-2026-5076) Leads to Account Takeover
slug: 2026-06-armember-insecure-password-reset
description: The ARMember Premium plugin for WordPress, in versions up to and including 7.3.1, contains an insecure password reset mechanism (CVE-2026-5076) that stores plaintext password reset keys in the `wp_usermeta` table, which, when chained with other vulnerabilities like SQL Injection (CVE-2026-5073, CVE-2026-5074), allows unauthenticated attackers to extract these plaintext keys to reset passwords and compromise any user account, including administrators, leading to account takeover.
date: "2026-06-14T20:15:05Z"
lastmod: "2026-08-31T13:04:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ZYCODER0DAY-CVE-2026-5076&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - plugin-vulnerability
  - account-takeover
  - sql-injection
  - password-reset
  - cve
  - web
vendors:
  - ARMember
  - WordPress
products:
  - ARMember Premium plugin <= 7.3.1 (<= 7.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
cves:
  - id: CVE-2026-5076
    cvss: 9.8
    epss: 0.00419
  - id: CVE-2026-5073
    cvss: 7.5
    epss: 0.01383
  - id: CVE-2026-5074
    cvss: 6.5
    epss: 0.00308
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5076
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5073
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5074
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ZYCODER0DAY-CVE-2026-5076&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-5076 Exploitation — Insecure ARMember Password Reset Attempt
    description: Detects exploitation attempts for CVE-2026-5076 where an attacker tries to use a plaintext password reset key via the ARMember plugin's custom 'armrp' action.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.002
    data_sources:
      - webserver
  - title: Detects CVE-2026-5073/CVE-2026-5074 Exploitation — ARMember SQL Injection Patterns
    description: Detects common SQL Injection patterns targeting ARMember plugin endpoints, which can lead to information disclosure including plaintext password reset keys (CVE-2026-5073, CVE-2026-5074).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1592
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-08-31T13:04:11Z"
    level: L2
    summary: poc_available; armember premium plugin <= 7.3.1 version <= 7.3.1
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ZYCODER0DAY-CVE-2026-5076&utm_source=rss&utm_medium=rss
---

The ARMember Premium plugin for WordPress, affecting all versions up to and including 7.3.1, harbors a critical insecure password reset vulnerability, CVE-2026-5076. This flaw stems from the plugin's practice of storing a plaintext copy of the password reset key in the `arm_reset_password_key` user meta field within the `wp_usermeta` database table. While WordPress core securely hashes and stores activation keys, ARMember's exposure of the plaintext key, when combined with other vulnerabilities such as SQL Injection (CVE-2026-5073, CVE-2026-5074), allows unauthenticated attackers to extract this sensitive information. This extraction facilitates the use of ARMember's custom `armrp` reset action to set a new password for any user, including high-privilege administrators, thereby enabling full account takeover and subsequent compromise of the entire WordPress site.

## Attack Chain

1.  **Initial Access / Vulnerability Chaining**: An unauthenticated attacker identifies a WordPress site running the vulnerable ARMember Premium plugin (versions <= 7.3.1).
2.  **SQL Injection Exploitation**: The attacker exploits a SQL Injection vulnerability (e.g., CVE-2026-5073, CVE-2026-5074) within the ARMember plugin via a crafted HTTP request.
3.  **Sensitive Data Extraction**: Through the SQL Injection, the attacker queries the `wp_usermeta` database table to extract the plaintext `arm_reset_password_key` associated with a high-privilege user (e.g., an administrator).
4.  **Insecure Password Reset Initiation**: The attacker initiates a password reset process for the targeted user, which causes the plugin to generate a new `arm_reset_password_key` in `wp_usermeta` (though the attacker uses the previously extracted key).
5.  **Password Reset Bypass**: The attacker crafts an HTTP request to the ARMember plugin's custom password reset endpoint (typically via the `armrp` action) using the plaintext `arm_reset_password_key` obtained in step 3 and a desired new password.
6.  **Account Takeover**: The vulnerable plugin validates the provided plaintext key and successfully updates the target user's password without proper authorization checks, granting control to the attacker.
7.  **Unauthorized Access**: The attacker logs into the WordPress site using the newly set credentials, gaining full control over the compromised user's account, potentially leading to administrative access and complete site compromise.

## Impact

The successful exploitation of CVE-2026-5076, particularly when chained with SQL Injection vulnerabilities, results in complete account takeover for any user on the affected WordPress site, including administrative accounts. This allows attackers to gain full control over the website, leading to arbitrary code execution, data manipulation or exfiltration, website defacement, or further compromises of connected systems. Organizations utilizing the ARMember Premium plugin are at critical risk, as administrative control over a WordPress site can severely impact business operations, reputation, and expose sensitive customer data.

## Recommendation

*   **Patch CVE-2026-5076, CVE-2026-5073, and CVE-2026-5074**: Immediately update the ARMember Premium plugin to a patched version (7.3.2 or later) to remediate these vulnerabilities.
*   **Deploy Detection Rules**: Deploy the Sigma rules provided in this brief to your SIEM/detection platform and tune them for your environment to detect exploitation attempts.
*   **Monitor Webserver Logs**: Actively monitor webserver logs for suspicious HTTP requests targeting ARMember plugin endpoints, particularly those containing SQL injection patterns or non-standard password reset parameters.
*   **Review `wp_usermeta`**: Conduct an audit of the `wp_usermeta` table to identify any stored plaintext `arm_reset_password_key` entries, although patching should prevent future storage.
