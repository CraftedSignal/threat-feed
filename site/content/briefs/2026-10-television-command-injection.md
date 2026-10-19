---
title: OS Command Injection in Television (tv) Package
slug: 2026-10-television-command-injection
description: The Television (tv) package, versions 0.15.0 through 0.15.9, is vulnerable to OS command injection due to improper sanitization of single quotes within the format_command function.
date: "2026-10-19T16:08:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:television:tv:0.15.0:*:*:*:*:*:*:*
  - cpe:2.3:a:television:tv:0.15.9:*:*:*:*:*:*:*
tags:
  - command-injection
  - vulnerability
  - supply-chain
products:
  - Television (0.15.0 - 0.15.9)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can plant a file with a crafted name containing an apostrophe so that triggering an action like the default edit action executes commands with victim privileges.
    confidence_band: high
cves:
  - id: CVE-2026-112263
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112263
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Television (tv) package to version 0.16.0 or later to patch CVE-2026-112263
      owner: IT Operations
      due: 48h
      evidence: NVD disclosure identifying vulnerability in 0.15.0-0.15.9
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected Television package versions
      owner: IT Operations
      addresses: CVE-2026-112263
      evidence: NVD CVE-2026-112263
---

The Television (tv) package, versions 0.15.0 through 0.15.9, contains a critical OS command injection vulnerability. The flaw exists within the 'format_command' function, which fails to properly escape single quotes when processing input. An attacker can exploit this by planting or introducing a file with a maliciously crafted name containing an apostrophe into a directory monitored or processed by the application. When the application performs an action, such as the default 'edit' action on the crafted filename, the underlying shell interprets the apostrophe as a command separator or escape, leading to the execution of arbitrary shell commands with the privileges of the user running the application. This vulnerability presents a significant risk to development environments or servers utilizing the 'tv' package to manage file operations or editing workflows.

## Impact

Successful exploitation allows for arbitrary code execution on the host machine with the privileges of the user running the Television package. This can lead to full system compromise, unauthorized data access, and further lateral movement within the network. The vulnerability affects users of the 'tv' package within the 0.15.x version range across all supported operating systems.

## Recommendation

Prioritized actions for security teams:
- Identify all instances of the 'tv' (Television) package within the environment via software composition analysis (SCA) or package manifest audits.
- Upgrade the 'tv' package to a version beyond 0.15.9 immediately to remediate the 'format_command' vulnerability associated with CVE-2026-112263.
- Implement file integrity monitoring on directories where the 'tv' package performs automated operations to detect the introduction of files with anomalous naming patterns.
