---
title: Path Traversal Vulnerability in Gopeed Archive Extraction
slug: 2026-09-gopeed-traversal
description: Gopeed through version 2.0.0-beta.3 contains a path traversal vulnerability in archive extraction that allows an attacker to write arbitrary files outside the designated directory when the AutoExtract feature is enabled.
date: "2026-09-20T00:16:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gopeed:gopeed:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - vulnerability
  - file-write
vendors:
  - Gopeed
products:
  - Gopeed (<= 2.0.0-beta.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Attackers can craft malicious archives with entries containing directory traversal sequences that bypass validation, enabling file write operations when users download and extract archives with AutoExtract enabled.
    confidence_band: high
cves:
  - id: CVE-2026-93992
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93992
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable AutoExtract feature in Gopeed configurations.
      owner: IT Operations
      due: 24h
      evidence: Source identifies AutoExtract as the mechanism enabling arbitrary file writes.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Gopeed to a patched version beyond 2.0.0-beta.3.
      owner: IT Operations
      addresses: CVE-2026-93992
      evidence: Source notes vulnerability in versions through 2.0.0-beta.3.
---

Gopeed versions up to and including 2.0.0-beta.3 are susceptible to a path traversal vulnerability during the archive extraction process. This flaw stems from improper validation of file paths within archive entries. When a user downloads a malicious archive and leverages the software's AutoExtract functionality, an attacker can utilize directory traversal sequences (such as ../) within the archive's internal path structure to escape the intended extraction folder. This capability allows the attacker to write or overwrite arbitrary files on the victim's filesystem. Successful exploitation could lead to system compromise, such as overwriting configuration files or placing malicious executables in startup directories, resulting in unauthorized code execution or persistence. This issue specifically impacts instances where the AutoExtract feature is actively enabled by the end user.

## Impact

The vulnerability allows for arbitrary file writes on the host system, which can result in full system compromise, loss of data integrity, and unauthorized remote code execution. Users in any sector utilizing Gopeed for file downloads are at risk if they enable the AutoExtract feature and process untrusted archives.

## Recommendation

Prioritized actions for security teams:
- Identify and audit all instances of Gopeed version 2.0.0-beta.3 or earlier across the environment.
- Disable the AutoExtract feature in Gopeed settings across all managed endpoints until an official patch is applied.
- Monitor for unauthorized file modifications in sensitive directories (e.g., startup folders, system binaries) if Gopeed is in use.
- Upgrade all Gopeed installations to a version released after 2.0.0-beta.3 once the vendor provides a remediation.
