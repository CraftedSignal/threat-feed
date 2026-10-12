---
title: Unrestricted File Upload Vulnerability in Thelia
slug: 2026-10-thelia-file-upload
description: An unrestricted file upload vulnerability in Thelia allows authenticated back-office users to achieve remote code execution by bypassing filename sanitization.
date: "2026-10-12T18:33:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:thelia:thelia:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - remote-code-execution
  - file-upload
vendors:
  - Thelia
products:
  - Thelia (< 3.1.2, 3.2.x < 3.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Thelia before 3.1.2 and 3.2.x before 3.2.1 contains an unrestricted file upload vulnerability.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: FileManager::sanitizeFileName() strips the space, storing an executable .php file under public/cache/documents/ for code execution.
    confidence_band: high
cves:
  - id: CVE-2026-109397
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109397
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Thelia installations to versions 3.1.2 or 3.2.1.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-109397 remediation guidance.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Thelia to 3.1.2 or 3.2.1.
      owner: IT Operations
      addresses: CVE-2026-109397
      evidence: Source advisory
---

Thelia versions before 3.1.2 and 3.2.x before 3.2.1 are vulnerable to an unrestricted file upload flaw (CVE-2026-109397). This vulnerability exists because the FileProcessorService performs filename validation on the raw input, while the subsequent FileManager::sanitizeFileName() function strips trailing spaces from the filename. An authenticated back-office user can exploit this discrepancy by appending a trailing space to a malicious PHP file's name. This causes the file to pass initial validation, after which the sanitization process converts it into a valid, executable .php file. The file is then stored in the public/cache/documents/ directory, where it can be directly accessed and executed by the web server, resulting in remote code execution with the permissions of the web server user.

## Impact

Successful exploitation of this vulnerability allows an authenticated back-office user to gain full remote code execution on the underlying web server. This can lead to complete compromise of the e-commerce platform, including unauthorized access to customer data, system configuration modification, and further lateral movement within the network. The severity is rated as high due to the potential for full system compromise from a common administrative interface.

## Recommendation

- Upgrade Thelia to version 3.1.2 or 3.2.1 immediately to patch CVE-2026-109397.
- Review access logs and application logs for suspicious file uploads or direct access requests to files located within the /public/cache/documents/ directory.
- Restrict access to the back-office administrative portal to trusted internal IP addresses and implement multi-factor authentication to reduce the likelihood of unauthorized account access.
