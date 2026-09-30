---
title: Path Traversal Vulnerability in ZeroClaw Plugin Installation
slug: 2026-09-zeroclaw-path-traversal
description: ZeroClaw versions before 0.8.5 are vulnerable to path traversal via the plugins-wasm feature, allowing attackers to overwrite arbitrary files through crafted plugin manifest files.
date: "2026-09-30T20:36:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zeroclaw:zeroclaw:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - remote-code-execution
vendors:
  - ZeroClaw
products:
  - ZeroClaw (< 0.8.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: Attackers can convince users to install crafted plugins that write arbitrary files to paths outside the plugins directory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: enabling code execution.
    confidence_band: high
cves:
  - id: CVE-2026-101885
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101885
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ZeroClaw to version 0.8.5 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-101885 patch release.
  mitigation_plan:
    - priority: immediate
      action: Disable plugins-wasm feature in ZeroClaw configuration.
      owner: IT Operations
      addresses: CVE-2026-101885
      evidence: Source notes the vulnerability is specific to the plugins-wasm feature.
---

ZeroClaw versions prior to 0.8.5 are susceptible to a path traversal vulnerability when the plugins-wasm feature is enabled. The vulnerability stems from insufficient input validation of the wasm_path field within the plugin manifest file during installation. An attacker can create a malicious plugin containing a crafted manifest file that specifies arbitrary filesystem locations for the plugin component. When a user installs the malicious plugin, the application fails to sanitize this path, resulting in the plugin writing or overwriting files outside the intended plugins directory. This behavior can be leveraged to overwrite sensitive system files or shell configuration scripts, potentially leading to remote code execution under the context of the user running the ZeroClaw application. This issue impacts all platforms where ZeroClaw is deployed if the vulnerable plugins-wasm feature is active.

## Impact

Successful exploitation allows for unauthorized file writes on the host system. By targeting shell startup files or other sensitive configuration locations, an attacker can achieve code execution, potentially leading to full system compromise or persistence. This vulnerability poses a high risk to environments where users frequently install third-party plugins from untrusted sources.

## Recommendation

- Upgrade ZeroClaw to version 0.8.5 or later to patch CVE-2026-101885.
- Disable the plugins-wasm feature if it is not required for operational workflows until the environment can be updated.
- Implement file integrity monitoring on critical configuration directories and shell startup scripts to detect unauthorized file modifications associated with plugin installation events.
