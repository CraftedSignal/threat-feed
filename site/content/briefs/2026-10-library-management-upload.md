---
title: Unrestricted File Upload Vulnerability in SourceCodester Library Management System
slug: 2026-10-library-management-upload
description: SourceCodester Library Management System 1.0 is vulnerable to an unrestricted file upload flaw via the 'image' argument in 'admin/add_admin.php', potentially enabling remote code execution.
date: "2026-10-13T08:33:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:library_management_system:1.0:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - unrestricted-upload
  - cve-2026-108975
vendors:
  - SourceCodester
products:
  - Library Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: This vulnerability allows remote attackers to upload arbitrary files, potentially leading to remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Performing a manipulation of the argument image results in unrestricted upload.
    confidence_band: high
cves:
  - id: CVE-2026-108975
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108975
rules:
  - title: Detect CVE-2026-108975 Exploitation - Unrestricted File Upload Attempt
    description: Detects potential exploitation of CVE-2026-108975 by monitoring for POST requests to admin/add_admin.php involving unexpected file types.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch or restrict access to admin/add_admin.php
      owner: IT Operations
      due: 48h
      evidence: Unrestricted file upload allows for RCE.
  hunt_leads:
    - lead: Search for files created in the web root that do not match expected image extensions.
      technique_id: T1505.003
      data_needed:
        - File system auditing logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability allows uploading arbitrary files which could be executable scripts.
  mitigation_plan:
    - priority: immediate
      action: Implement strict file type and extension validation.
      owner: IT Operations
      addresses: CVE-2026-108975
      evidence: Vulnerability allows unrestricted upload.
---

A security vulnerability has been identified in SourceCodester Library Management System version 1.0 that permits unrestricted file uploads. The flaw resides in the 'admin/add_admin.php' file, specifically within the handling of the 'image' argument during the 'move_uploaded_file' function execution. By manipulating this argument, an unauthenticated remote attacker can bypass file type validation to upload arbitrary files, such as malicious scripts, to the web server. This vulnerability has publicly available exploit code, increasing the likelihood of exploitation. Successful exploitation can lead to remote code execution (RCE) by accessing the uploaded file through the web application's document root, granting the attacker the ability to execute commands in the context of the web server service.

## Impact

The vulnerability allows for remote code execution, which could lead to full system compromise of the underlying web server hosting the application. This poses a critical risk to data confidentiality and integrity for any organization currently running version 1.0 of the SourceCodester Library Management System.

## Recommendation

1. Identify all instances of SourceCodester Library Management System 1.0 within the environment.
2. If the application cannot be patched or upgraded to a version where this vulnerability is remediated, restrict access to the 'admin/add_admin.php' endpoint to trusted administrative IP addresses via web server access controls.
3. Monitor web server logs for HTTP POST requests directed at 'admin/add_admin.php' containing suspicious filenames or content-types in the 'image' parameter.
4. Implement strict file extension filtering and mime-type verification on the server side to prevent the upload of executable scripts (e.g., .php, .php5, .phtml).
