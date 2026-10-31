---
brief_id: brief-2026-10-31-markus-zip-slip
event_id: brief-2026-10-31-markus-zip-slip
revision: 1
activity_at: "2026-10-31T01:03:26Z"
title: 'MarkUs: Zip Slip remote code execution (CVE-2026-25057)'
slug: 2026-10-markus-zip-slip
description: An authenticated instructor-level user can exploit a Zip Slip vulnerability in MarkUs assignment configuration uploads to write arbitrary files and achieve remote code execution.
date: "2026-10-31T01:03:26Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation for file upload logging.
cpes:
  - cpe:2.3:a:markusproject:markus:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - rce
  - path-traversal
  - zip-slip
vendors:
  - MarkUsProject
products:
  - MarkUs (< 2.9.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Загрузка ZIP-архивов с конфигурацией заданий в MarkUs уязвима к обходу путей (Zip Slip), что позволяет записывать произвольные файлы и приводит к удалённому выполнению кода.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Перезапись исполняемых файлов приложения может привести к удалённому выполнению кода.
    confidence_band: high
cves:
  - id: CVE-2026-25057
    cvss: 9.1
    epss: 0.00533
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-USTR-CVE-2026-25057
  - https://github.com/ustr/cve-2026-25057/blob/main/poc.py
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-USTR-CVE-2026-25057&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all MarkUs deployments and restrict access to the configuration upload functionality to known, authorized instructor accounts.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability requires authenticated instructor-level access.
  hunt_leads:
    - lead: Identify unusual file system writes within the MarkUs application directory, specifically following requests to the assignment configuration upload endpoint.
      technique_id: T1059
      data_needed:
        - Web server access logs (cs-uri-stem)
        - File integrity monitoring (FIM) or OS-level file creation events
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The exploit involves writing files outside the intended destination via path traversal.
  mitigation_plan:
    - priority: immediate
      action: Patch MarkUs to 2.9.1 or later
      owner: IT Operations
      addresses: CVE-2026-25057
      evidence: Standard patch management for critical vulnerabilities.
---

MarkUs, a web-based assignment grading application, is vulnerable to a Zip Slip path traversal vulnerability (CVE-2026-25057). The vulnerability exists in the assignment configuration ZIP upload functionality, where archive entry names are used to build filesystem paths without proper validation. An authenticated user with instructor privileges can upload a crafted ZIP file containing traversal sequences to overwrite files on the underlying host, potentially leading to remote code execution (RCE).

## Attack Chain
1. Actor authenticates to the MarkUs web interface with instructor-level privileges.
2. Actor navigates to the 'Assignments' section of a course.
3. Actor selects the 'Upload the configuration zip file' option.
4. Actor submits a specially crafted ZIP archive containing malicious file paths with traversal sequences.
5. The application extracts the archive, writing files outside the intended destination directory.
6. The application overwrites a critical executable or configuration file, enabling subsequent remote command execution.

## Impact
Successful exploitation allows for arbitrary file writes with the privileges of the web application process. This may lead to total compromise of the server if the attacker can overwrite executable application files or startup scripts.

## Recommendation
- Inventory all instances of MarkUs in the environment.
- Apply security patches provided by the MarkUsProject as soon as they are available.
- Audit logs for 'Assignments' configuration file upload activity, particularly by instructor-level accounts.
- Implement restrictive filesystem permissions for the web application user to limit the impact of potential file overwrite attacks.
