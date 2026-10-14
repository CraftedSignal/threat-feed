---
title: OS Command Injection in KDE Dolphin via Crafted Folder Names
slug: 2026-10-kde-dolphin-rce
description: KDE Dolphin versions 24.08.0 through 26.08.2 are vulnerable to OS command injection through improper sanitization of directory names used in the slotDoubleClickViewBackground function.
date: "2026-10-14T04:38:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kde:dolphin:24.08.0:*:*:*:*:*:*:*
  - cpe:2.3:a:kde:dolphin:26.08.2:*:*:*:*:*:*:*
tags:
  - command-injection
  - linux
  - kde
vendors:
  - KDE
products:
  - Dolphin (24.08.0-26.08.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can embed a double quote and shell metacharacters in a directory name to escape quoting in slotDoubleClickViewBackground, executing commands.
    confidence_band: high
cves:
  - id: CVE-2026-110236
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110236
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update KDE Dolphin to the latest patched version
      owner: IT Operations
      addresses: CVE-2026-110236
      evidence: NVD vulnerability disclosure
---

KDE Dolphin versions 24.08.0 through 26.08.2 are susceptible to an OS command injection vulnerability (CVE-2026-110236). The flaw exists within the slotDoubleClickViewBackground function, which fails to adequately sanitize directory names before substituting them into a path placeholder. An attacker can create a folder with a malicious name containing shell metacharacters and double quotes, designed to break out of the intended command context. When an authenticated user performs a double-click on the background of a directory view within Dolphin, the application inadvertently executes the embedded malicious commands. This vulnerability allows for arbitrary command execution under the context of the user running the Dolphin process, potentially leading to unauthorized data access or further system compromise. Users of the affected versions should update to the latest available release to mitigate this risk.

## Impact

The vulnerability affects users of the KDE desktop environment utilizing Dolphin as a file manager. Successful exploitation allows for arbitrary code execution with the user's privileges, which may result in data exfiltration, modification of user files, or the installation of persistent malicious payloads. The severity is marked as high due to the potential for local system compromise.

## Recommendation

* Update to the latest version of KDE Dolphin, which includes the fix for CVE-2026-110236.
* Audit file systems for unusually named directories containing shell metacharacters (e.g., ;, |, &, $, `) which may indicate attempts to leverage this vulnerability.
