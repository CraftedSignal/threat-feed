---
brief_id: brief-2026-10-24-visitor-management-system-rce
event_id: brief-2026-10-24-visitor-management-system-rce
revision: 1
activity_at: "2026-10-24T04:06:00Z"
title: 'Visitor Management System: SQL injection and unrestricted file upload (CVE-2026-10170)'
slug: 2026-10-visitor-management-system-rce
description: Visitor Management System 1.0 is vulnerable to a critical attack chain where SQL injection in 'pass.php' leads to plaintext credential theft and subsequent unrestricted file upload in 'admin_user_0.php' for remote code execution.
date: "2026-10-24T04:06:00Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:code_projects_org:visitor_management_system:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - rce
  - sqli
  - arbitrary-file-upload
vendors:
  - code-projects.org
products:
  - Visitor Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Visitor Management System 1.0 by code-projects.org is vulnerable to a critical attack chain combining SQL Injection and Unrestricted File Upload leading to Remote Code Execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: The uploaded webshell is stored in a web-accessible directory and can be executed directly via URL, resulting in full Remote Code Execution on the server.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Using the extracted credentials to authenticate as admin, the attacker can then upload a PHP webshell.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: Web Shell
    evidence: The uploaded webshell is stored in a web-accessible directory and can be executed directly via URL.
    confidence_band: high
cves:
  - id: CVE-2026-10170
    cvss: 6.3
    epss: 0.00244
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-XMYRONN-CVE-2026-10170-RCE
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-XMYRONN-CVE-2026-10170-RCE&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-10170 Exploitation - SQL Injection via phone parameter
    description: Detects SQL injection attempts against the phone parameter in pass.php by searching for common SQL syntax characters in HTTP POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-10170 Exploitation - Webshell access via /folder/
    description: Detects access to potential webshells uploaded within the VMS application directory.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all instances of Visitor Management System (1.0) and restrict external access.
      owner: IT Operations
      due: 24h
      evidence: The application is vulnerable to an RCE attack chain via public-facing endpoints.
  hunt_leads:
    - lead: Search web server logs for HTTP POST requests to /vms/php/pass.php containing SQL injection patterns or GET requests to /vms/php/folder/ containing 'cmd='.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The attack chain utilizes pass.php for SQLi and a folder within the application path to store webshells.
  mitigation_plan:
    - priority: immediate
      action: Remove or restrict permissions for the `/vms/php/folder/` directory to prevent webshell execution.
      owner: IT Operations
      addresses: Unrestricted file upload in admin_user_0.php
      evidence: The webshell is stored in a web-accessible directory and executed via URL.
---

Visitor Management System 1.0, developed by code-projects.org, contains a critical attack chain involving two distinct vulnerabilities: a SQL injection (CWE-89) in `pass.php` and an unrestricted file upload (CWE-434) in `admin_user_0.php`. Successful exploitation allows an attacker with low-privileged access to exfiltrate administrative credentials stored in plaintext and subsequently execute arbitrary OS commands on the host server.

## Attack Chain

1. Attacker authenticates as a low-privileged user (e.g., guard account).
2. Attacker interacts with `/vms/php/phone_0.php` and injects SQL commands into the `phone` POST parameter.
3. Attacker uses SQL injection to exfiltrate the `login_user` table from the `vms` database.
4. Attacker recovers plaintext administrative credentials from the dump.
5. Attacker authenticates to the application using the harvested admin credentials.
6. Attacker navigates to the Admin User management panel at `/vms/php/admin_user_0.php`.
7. Attacker uploads a malicious PHP webshell through the profile image upload field, which lacks file validation.
8. Attacker accesses the uploaded webshell via a direct URL and executes OS commands to achieve full system compromise.

## Impact

Successful exploitation results in full database compromise, unauthorized administrative access, and arbitrary code execution on the underlying server. Because passwords are stored in plaintext within the database, the impact is magnified as no further cracking effort is required by an attacker.

## Recommendation

- Immediately restrict access to the Visitor Management System to authorized networks or require robust multi-factor authentication for all users.
- Audit the `/vms/php/` directory for any unauthorized files, specifically `.php` files created by non-administrative users.
- Apply strict file-type validation and extension filtering on all upload inputs within the application.
- Implement parameterized queries across all database interaction modules to remediate the SQL injection vulnerability.
- Upgrade or patch Visitor Management System if a fix becomes available from code-projects.org.
