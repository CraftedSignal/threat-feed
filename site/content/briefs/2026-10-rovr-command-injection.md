---
title: OS Command Injection in Rovr via Malicious Filenames
slug: 2026-10-rovr-command-injection
description: Rovr through 0.10.3 contains an OS command injection vulnerability triggered by opening files with malicious names containing shell metacharacters, enabling arbitrary code execution under the user's context.
date: "2026-10-14T04:38:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rovr:rovr:*:*:*:*:*:*:*:*
tags:
  - cve-2026-110233
  - command-injection
  - windows
  - execution
vendors:
  - Rovr
products:
  - Rovr (<= 0.10.3)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can craft a file name with characters such as '&' to achieve arbitrary command execution under the context of the user running the application via the open_file function.
    confidence_band: high
cves:
  - id: CVE-2026-110233
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110233
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all instances of Rovr to a version beyond 0.10.3
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-110233 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade Rovr to latest version to patch CVE-2026-110233
      owner: IT Operations
      addresses: CVE-2026-110233
      evidence: NVD vulnerability disclosure
---

Rovr versions through 0.10.3 are affected by an OS command injection vulnerability residing in the application's file handling logic. The vulnerability exists within the open_file function, which fails to properly sanitize filenames before processing them in a system shell. An attacker can exploit this by distributing files with specially crafted names containing shell metacharacters, such as the ampersand (&). When a user opens such a file using the vulnerable Rovr application on a Windows system, the application inadvertently interprets the filename as part of a shell command, leading to the execution of arbitrary commands with the privileges of the user running the process. This vulnerability is particularly concerning as it relies on common user interaction - opening a file - to achieve compromise.

## Impact

Successful exploitation allows for unauthorized code execution within the security context of the logged-in user. This may lead to further system compromise, data exfiltration, or the deployment of additional malicious payloads. The scope of targeting is limited to users of Rovr versions 0.10.3 and below on Windows platforms.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Patch Rovr to a version beyond 0.10.3 immediately to remediate CVE-2026-110233.
- Implement monitoring for suspicious child processes spawned by the Rovr application, such as cmd.exe or powershell.exe, which should not occur during standard file opening operations.
