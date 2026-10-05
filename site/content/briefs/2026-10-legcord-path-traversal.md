---
title: Path Traversal Vulnerability in Legcord Theme IPC Handlers
slug: 2026-10-legcord-path-traversal
description: Legcord versions 1.1.0 through 1.3.0 contain a path traversal vulnerability in IPC handlers that allows arbitrary file system manipulation and command execution when triggered via cross-origin script injection.
date: "2026-10-05T01:43:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:legcord:legcord:1.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:legcord:legcord:1.3.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - code-execution
vendors:
  - Legcord
products:
  - Legcord (1.1.0 through 1.3.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Attackers... can abuse themes.folder, themes.uninstall, and themes.install to launch local executables.
    confidence_band: high
cves:
  - id: CVE-2026-105293
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105293
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Legcord to the latest version to mitigate CVE-2026-105293.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-105293
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 1.3.1 or higher once available.
      owner: IT Operations
      addresses: CVE-2026-105293
      evidence: NVD vulnerability disclosure
---

Legcord versions 1.1.0 through 1.3.0 are susceptible to a path traversal vulnerability within their theme inter-process communication (IPC) handlers. The flaw exists because the application fails to adequately validate 'theme id' parameters before processing them. An attacker who has achieved script execution within the Discord origin, perhaps through a secondary XSS attack, can leverage the 'themes.folder', 'themes.uninstall', and 'themes.install' IPC handlers to break out of the intended themes directory. This access grants the ability to perform unauthorized file operations, including recursive directory deletion and arbitrary file writes, as well as the execution of local binaries on the host system. This vulnerability poses a significant risk to host integrity for users of the affected Legcord versions.

## Impact

Successful exploitation of CVE-2026-105293 allows for arbitrary code execution, unauthorized data destruction, and unauthorized file system modification on the host system where Legcord is installed. By escaping the application sandbox, an attacker can impact the entire user profile, potentially leading to persistent malware installation or data exfiltration.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Upgrade Legcord to a version beyond 1.3.0 immediately once a patch is released by the maintainers.
- Monitor for anomalous process creation events originating from the Legcord process tree, particularly those involving non-standard child processes.
- Implement endpoint controls to restrict the execution of binaries located within or spawned from user-writable application directories associated with Legcord.
