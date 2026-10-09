---
title: LobsterAI Arbitrary File Deletion Vulnerability
slug: 2026-10-lobsterai-arbitrary-deletion
description: LobsterAI versions 2026.5.27 through 2026.9.23 contain an arbitrary file deletion vulnerability in the skills:delete IPC handler, allowing attackers to delete arbitrary user-writable directories via malicious skill manifests.
date: "2026-10-09T17:25:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lobsterai:lobsterai:2026.5.27:*:*:*:*:*:*:*
  - cpe:2.3:a:lobsterai:lobsterai:2026.9.23:*:*:*:*:*:*:*
vendors:
  - LobsterAI
products:
  - LobsterAI (2026.5.27 through 2026.9.23)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers who convince a user to install a crafted skill can make uninstallation recursively delete arbitrary user-writable directories.
    confidence_band: high
cves:
  - id: CVE-2026-108156
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108156
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade LobsterAI to the latest version to patch CVE-2026-108156
      owner: IT Operations
      due: 48h
      evidence: Source advisory identifies vulnerability in versions 2026.5.27 through 2026.9.23
  mitigation_plan:
    - priority: immediate
      action: Upgrade LobsterAI to a version beyond 2026.9.23
      owner: IT Operations
      addresses: CVE-2026-108156
      evidence: NVD advisory for CVE-2026-108156
---

LobsterAI versions 2026.5.27 through 2026.9.23 are affected by an external control of file path vulnerability (CVE-2026-108156) within the skills:delete IPC handler. The vulnerability exists because the application trusts the 'openclawSourceDir' parameter defined in a skill's '_meta.json' file during the uninstallation process. An attacker can craft a malicious skill package with a manipulated 'openclawSourceDir' value. When a victim installs and subsequently uninstalls the malicious skill, the LobsterAI application performs a recursive deletion operation on the path specified in the configuration. Because the product's security scanner fails to validate the contents of '_meta.json', the application can be coerced into deleting sensitive, user-writable directories, including the user's home directory. This vulnerability poses a significant risk to data integrity for users of the LobsterAI platform.

## Impact

Successful exploitation of this vulnerability results in the unauthorized deletion of arbitrary directories and files within the scope of the user's permissions on the host system. This could lead to partial or complete loss of user data, disruption of system operations, and potential application instability. The scope of impact is limited to directories writable by the user running the LobsterAI application.

## Recommendation

Prioritized actions for security teams:
- Update LobsterAI to a version later than 2026.9.23 immediately to address the vulnerability in the skills:delete IPC handler.
- Audit existing installed skills for suspicious or unauthorized '_meta.json' files containing modified 'openclawSourceDir' parameters if the software cannot be patched immediately.
- Implement file integrity monitoring (FIM) or access logging on sensitive user directories to detect recursive file deletion events initiated by the LobsterAI process.
