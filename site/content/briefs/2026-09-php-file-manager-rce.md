---
title: Unrestricted File Upload Vulnerability in php-file-manager-with-code-editor
slug: 2026-09-php-file-manager-rce
description: A vulnerability (CVE-2026-95499) in php-file-manager-with-code-editor versions 3.0 and earlier allows remote attackers to perform unrestricted file uploads by manipulating the 'files' argument.
date: "2026-09-22T14:36:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:josephchuks:php-file-manager-with-code-editor:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - remote-code-execution
  - file-upload
  - cve-2026-95499
vendors:
  - JosephChuks
products:
  - php-file-manager-with-code-editor (<= 3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: Executing a manipulation of the argument files can lead to unrestricted upload.
    confidence_band: high
cves:
  - id: CVE-2026-95499
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95499
rules:
  - title: Detects CVE-2026-95499 Exploitation - Suspicious File Upload
    description: Detects potential exploitation of CVE-2026-95499 by monitoring for POST requests to filemanager.php involving file upload parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1505.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate web servers hosting php-file-manager-with-code-editor from external network access.
      owner: IT Operations
      due: 24h
      evidence: Source confirms remote exploitation capability for CVE-2026-95499.
  mitigation_plan:
    - priority: immediate
      action: Disable or remove the affected application until a secure version is released.
      owner: IT Operations
      addresses: CVE-2026-95499
      evidence: Vendor remains unresponsive; no patches available.
---

CVE-2026-95499 identifies a critical security flaw in the 'php-file-manager-with-code-editor' application, specifically affecting versions up to 3.0. The vulnerability stems from insecure handling of user-supplied data in the 'files' argument passed to the 'move_uploaded_file' function within 'filemanager.php'. This flaw permits remote, unauthenticated attackers to bypass intended restrictions and upload arbitrary files - potentially including malicious PHP scripts - directly to the web server's filesystem. Given the application's nature as a file manager and code editor, successful exploitation leads to remote code execution (RCE) as the web service user. The vendor was notified of the disclosure but remained unresponsive, leaving the vulnerability unpatched in the latest version. Organizations hosting this software are at significant risk of complete server compromise if exposed to the internet.

## Impact

Successful exploitation allows for the execution of arbitrary code on the underlying host, facilitating data exfiltration, lateral movement, or complete system takeover. As the affected software is intended for managing files and editing code, attackers can easily maintain persistence or leverage existing server functionality to extend their access. There are no known patches, making decommissioning or strict network isolation the primary defensive measures.

## Recommendation

* Immediately isolate the host running php-file-manager-with-code-editor from the internet.
* If the service is required, implement stringent web application firewall (WAF) rules to inspect and block POST requests to 'filemanager.php' that contain suspicious file extensions (e.g., .php, .phtml, .php7) within the 'files' parameter.
* Audit the server filesystem for unexpected files in directories managed by the application, focusing on web-accessible paths.
* Review web server access logs for anomalous POST requests directed at 'filemanager.php' that do not originate from expected administrative IP addresses.
