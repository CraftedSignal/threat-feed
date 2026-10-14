---
title: Vifm Local Privilege Escalation via Insecure IPC FIFO
slug: 2026-10-vifm-fifo-privesc
description: Vifm versions 0.8.1-beta through 0.14.4 are vulnerable to local command injection and privilege escalation due to insecure IPC FIFO reuse in shared temporary directories.
date: "2026-10-14T04:38:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vifm:vifm:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - linux
  - macos
  - ipc
vendors:
  - Vifm
products:
  - Vifm (0.8.1-beta through 0.14.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Vifm ... reuses a pre-existing IPC FIFO in the shared temporary directory without checking ownership, allowing local users to execute commands as another user.
    confidence_band: high
cves:
  - id: CVE-2026-110237
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110237
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review and restrict write permissions on shared temporary directories in multi-user environments.
      owner: IT Operations
      due: 72h
      evidence: Source document identifies insecure handling of FIFO in shared temp directory.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Vifm to the latest patched version when available.
      owner: IT Operations
      addresses: CVE-2026-110237
      evidence: NVD advisory for CVE-2026-110237.
---

Vifm, a file manager for Unix-like systems, contains a local privilege escalation vulnerability (CVE-2026-110237) affecting versions 0.8.1-beta through 0.14.4. The vulnerability stems from the application's insecure handling of Inter-Process Communication (IPC) via First-In, First-Out (FIFO) pipes. Specifically, Vifm attempts to use a FIFO file located in a shared temporary directory without verifying the ownership or permissions of that file.

A local attacker with access to the same shared directory can pre-create a FIFO named 'vifm-ipc-vifm'. When a victim user launches Vifm, the application connects to this attacker-controlled pipe. The attacker can then inject IPC packets containing the '-c' flag and '!shell' commands, which are subsequently executed by the Vifm process under the victim's security context. This allows an attacker to escalate privileges to match the victim user's session, which is particularly critical if a more privileged user or administrator executes Vifm in a directory where a lower-privileged user has created the malicious pipe.

## Impact

Successful exploitation allows a local attacker to execute arbitrary commands with the privileges of any user who subsequently launches the vulnerable version of Vifm. This can lead to full account takeover or unauthorized access to the victim's files and environment. The impact is significant for multi-user Linux or macOS systems where Vifm is used by administrative personnel.

## Recommendation

1. Upgrade Vifm to a patched version once released by the maintainers; monitor the Vifm project repositories for the official fix.
2. Implement local monitoring for the creation of FIFO files in world-writable directories like '/tmp' or '/var/tmp' that match the naming pattern 'vifm-ipc-vifm'.
3. Restrict write access to shared temporary directories where possible or enforce the use of private temporary directories for individual users to prevent malicious pipe pre-creation.
