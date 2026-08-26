---
title: Active Exploitation of Windows IKE Extension RCE
slug: 2026-08-windows-ike-rce
description: CVE-2022-34721 is a critical remote code execution vulnerability in the Windows Internet Key Exchange (IKE) extension, which is being actively exploited in the wild to gain unauthorized code execution.
date: "2026-08-26T05:08:41Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10:20h2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10:21h1:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10:21h2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_8.1:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_rt_8.1:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:azure:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows an unauthenticated, remote attacker to trigger code execution on vulnerable Windows systems by sending a specially crafted IP packet to a target.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: CVE-2022-34721 is a critical remote code execution vulnerability.
    confidence_band: high
cves:
  - id: CVE-2022-34721
    cvss: 9.8
    epss: 0.7855
references:
  - https://www.bleepingcomputer.com/news/security/cisa-critical-windows-ike-extension-flaw-now-exploited-in-attacks
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch CVE-2022-34721 on all internet-facing Windows systems
      owner: IT Operations
      due: 24h
      evidence: Active exploitation confirmed
---

CVE-2022-34721 is a critical remote code execution (RCE) vulnerability residing within the Windows Internet Key Exchange (IKE) extension. This vulnerability allows an unauthenticated, remote attacker to trigger arbitrary code execution on target systems by sending a specially crafted IP packet to a vulnerable host. Because the IKE protocol is frequently used in VPN implementations and network tunneling, this flaw presents a high-risk vector for remote exploitation, particularly for internet-facing systems that have the IKE service enabled. The vulnerability has been confirmed as being actively exploited in the wild, necessitating immediate patching. Defenders should focus on network-level segmentation for IKE-enabled services and ensure that all affected Windows environments are updated to mitigate the risk of unauthorized access and potential system compromise.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary code with elevated privileges on target Windows systems. This poses a significant threat to internal network security, as attackers can leverage this access for lateral movement, data exfiltration, or the deployment of further malicious payloads. The widespread use of IKE in network infrastructure means the potential attack surface is broad, and active exploitation in the wild suggests that threat actors are actively scanning for and compromising vulnerable hosts to achieve long-term persistence within targeted networks.

## Recommendation

* Prioritize the installation of security updates for CVE-2022-34721 across all internet-facing Windows servers immediately.
* Restrict network access to IKE/IPsec services at the perimeter to authorized IP ranges only, reducing the available attack surface for external unauthenticated actors.
* Monitor network perimeter logs for anomalous IP fragmentation or malformed packet patterns directed at UDP port 500 or 4500, which are typically used for IKE/IPsec traffic.
