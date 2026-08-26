---
title: Path Traversal Vulnerability in SourceCodester SRMS
slug: 2026-08-srms-path-traversal
description: SourceCodester Student Result Management System 1.0 contains a path traversal vulnerability (CVE-2025-4720) in the drop_student.php endpoint, allowing authenticated attackers to perform arbitrary file deletion via the 'img' parameter.
date: "2026-08-26T20:27:12Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:munyweki:student_result_management_system:1.0:*:*:*:*:*:*:*
vendors:
  - SourceCodester
products:
  - Student Result Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability in drop_student.php allows unauthorized file deletion, facilitating exploitation of a public-facing application endpoint.
    confidence_band: high
cves:
  - id: CVE-2025-4720
    cvss: 5.4
    epss: 0.00592
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-XMYRONN-DUPLICATE-CVE-2025-4720-
rules:
  - title: Detect CVE-2025-4720 Exploitation - Path Traversal in drop_student.php
    description: Detects attempts to exploit the path traversal vulnerability in drop_student.php by identifying directory traversal sequences in the img parameter
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to web server monitoring stack.
      owner: Detection Engineering
      due: 24h
      evidence: Source document identifies vulnerable endpoint and parameter.
  mitigation_plan:
    - priority: immediate
      action: Remove or sanitize input handling in drop_student.php.
      owner: IT Operations
      addresses: CVE-2025-4720
      evidence: Code review indicates lack of input validation on img parameter.
---

The Munyweki Student Result Management System (SRMS) version 1.0 is susceptible to a path traversal vulnerability identified as CVE-2025-4720. The vulnerability exists within the `academic/core/drop_student.php` script, which processes user-controlled input from the `img` GET parameter. The application fails to sanitize this input before passing it to the PHP `unlink()` function. Consequently, an authenticated attacker can traverse the file system by providing directory traversal sequences (e.g., ../) in the parameter, leading to the unauthorized deletion of arbitrary files located on the server. The lack of validation on the `img` input makes the system highly vulnerable to destructive actions if an attacker gains authenticated access.

## Attack Chain

1. Attacker performs reconnaissance to identify the presence of the SRMS 1.0 application.
2. Attacker obtains valid credentials to authenticate to the SRMS platform.
3. Attacker navigates to the `academic/core/drop_student.php` administrative function.
4. Attacker crafts a malicious GET request containing a path traversal payload in the `img` parameter (e.g., `?img=../../../../config.php`).
5. The server-side script receives the payload and directly passes the unsanitized string to the `unlink()` function.
6. The `unlink()` function executes the deletion against the resolved file path on the web server.
7. Targeted system files are deleted, potentially causing denial of service or configuration loss.

## Impact

Successful exploitation of CVE-2025-4720 allows an authenticated attacker to delete arbitrary files on the underlying web server. This could result in the destruction of critical application configuration files, database backups, or core system files, leading to a complete denial of service of the Student Result Management System.

## Recommendation

Prioritized actions for detection and remediation:
- Deploy the provided Sigma rule to monitor for suspicious path traversal patterns in web server logs targeting `drop_student.php`.
- Review web server access logs for any requests to `drop_student.php` containing `../` sequences in the `img` query parameter.
- Audit the file system permissions of the web application directory to ensure the web server service account has the minimum necessary privileges to prevent unauthorized file deletion.
- Patch or disable the vulnerable `academic/core/drop_student.php` component if it is not strictly required for business operations.
