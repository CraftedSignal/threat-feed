---
title: Remote Code Execution in BookStack via ZIP Import
slug: 2026-08-bookstack-rce
description: BookStack before version 26.05.4 is vulnerable to remote code execution due to improper validation of files within the portable ZIP import functionality.
date: "2026-08-29T15:39:54Z"
lastmod: "2026-09-02T03:10:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bookstackapp:bookstack:*:*:*:*:*:*:*:*
vendors:
  - BookStack
products:
  - BookStack (< 26.05.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: BookStack before 26.05.4 contains a remote code execution vulnerability in the portable ZIP import functionality that allows users with Import Content and Create Books permissions to upload a PHP polyglot file as a book cover.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: BookStack before 26.05.4 contains a stored cross-site scripting vulnerability in the drawing upload endpoint that accepts unvalidated base64 content.
    confidence_band: high
cves:
  - id: CVE-2026-82450
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82450
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84695
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade BookStack to version 26.05.4 or later to address CVE-2026-82450.
      owner: IT Operations
      due: 24h
      evidence: Source documentation for CVE-2026-82450
  hunt_leads:
    - lead: Audit public web root for unexpected PHP files uploaded via import features.
      technique_id: T1203
      data_needed:
        - File system modification logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows storage of malicious PHP files in the web root.
  mitigation_plan:
    - priority: immediate
      action: Upgrade BookStack to 26.05.4
      owner: IT Operations
      addresses: CVE-2026-82450
      evidence: NVD vulnerability details
updates:
  - at: "2026-09-02T03:10:38Z"
    level: L2
    summary: added coverage for BookStack (< 26.05.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84695
---

BookStack versions prior to 26.05.4 are susceptible to a remote code execution vulnerability located in the portable ZIP import feature. The flaw arises from insufficient validation of file extensions within ZIP archives. An authenticated user possessing 'Import Content' and 'Create Books' permissions can upload a ZIP archive containing a PHP polyglot file disguised as a book cover image. The application extracts the malicious file and stores it within the public web root directory. Because the system does not properly sanitize or verify the contents of the ZIP, the attacker can subsequently trigger the execution of the stored PHP script by making a direct, unauthenticated HTTP request to the location of the uploaded file. This vulnerability poses a significant risk as it allows for arbitrary code execution on the underlying server.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to achieve arbitrary remote code execution on the server hosting the BookStack application. This can lead to full system compromise, data exfiltration, or the deployment of persistent backdoors within the organization's infrastructure.

## Recommendation

- Upgrade the BookStack instance to version 26.05.4 or later immediately.
- Review the permissions of accounts with 'Import Content' and 'Create Books' access to ensure the principle of least privilege is maintained.
- Audit the web root directory for unauthorized .php files that do not correspond to the legitimate application structure.
