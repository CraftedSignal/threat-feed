---
title: Arbitrary File Write in Budibase Server via PWA Icon Upload
slug: 2026-09-budibase-arbitrary-file-write
description: Budibase Server versions prior to 3.45.0 allow authenticated BUILDER role users to achieve arbitrary file write and remote code execution by uploading malicious ZIP archives to the PWA icon upload endpoint.
date: "2026-09-26T15:11:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:budibase:budibase:*:*:*:*:*:*:*:*
tags:
  - arbitrary-file-write
  - rce
  - web-vulnerability
vendors:
  - Budibase
products:
  - Budibase Server (< 3.45.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: An authenticated attacker with BUILDER role can write arbitrary files as root, enabling remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-100682
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100682
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Budibase Server to version 3.45.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-100682 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade Budibase Server to 3.45.0
      owner: IT Operations
      addresses: CVE-2026-100682
      evidence: NVD advisory
---

Budibase Server versions before 3.45.0 are susceptible to an arbitrary file write vulnerability within the PWA (Progressive Web App) icon upload functionality. The application fails to properly validate symlink entries when extracting user-supplied ZIP archives. By crafting a ZIP file containing specific symlink structures combined with duplicate file entries, an authenticated attacker possessing the BUILDER role can traverse the filesystem to overwrite sensitive files. This vulnerability facilitates arbitrary code execution as the root user, significantly impacting the confidentiality, integrity, and availability of the host environment. Defenders should prioritize patching to version 3.45.0 or later and audit access logs for suspicious administrative activity within the Budibase management interface.

## Impact

Successful exploitation allows an attacker to gain remote code execution with root-level privileges on the server hosting the Budibase instance. This provides complete control over the application environment and the underlying host. The vulnerability specifically targets the Budibase Server software in enterprise environments where the BUILDER role is assigned to users.

## Recommendation

* Patch Budibase Server to version 3.45.0 or later immediately to address CVE-2026-100682.
* Review administrative access controls and audit users assigned the BUILDER role to minimize the attack surface.
* Monitor webserver access logs for anomalous POST requests directed at PWA icon upload endpoints.
