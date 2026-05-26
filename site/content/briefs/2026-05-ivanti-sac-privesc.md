---
title: 'Ivanti Secure Access Client: Local Privilege Escalation Vulnerabilities'
slug: 2026-05-ivanti-sac-privesc
description: A local attacker can exploit vulnerabilities in Ivanti Secure Access Client to manipulate files or escalate privileges, potentially gaining elevated access to the system.
date: "2026-05-26T12:20:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - ivanti
  - windows
  - linux
  - macos
vendors:
  - Ivanti
products:
  - Secure Access Client
affected_os:
  - windows
  - linux
  - macos
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1502
rules:
  - title: Detect Suspicious Ivanti Child Processes
    description: Detects suspicious child processes spawned by Ivanti Secure Access Client, potentially indicating exploitation or malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows|linux|macos
  - title: Detect Ivanti File Modifications
    description: Detects file modifications within the Ivanti Secure Access Client installation directories, which could indicate malicious activity related to privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1574
    data_sources:
      - file_event
      - windows|linux|macos
rules_count: 2
---

Ivanti Secure Access Client is susceptible to multiple vulnerabilities that can be exploited by a local attacker. This allows the attacker to manipulate files or escalate their privileges on the affected system. While the specific CVEs are not listed in the advisory, the potential impact of privilege escalation makes this a noteworthy threat for organizations using the Ivanti Secure Access Client. The advisory was published on 2026-05-26, highlighting the ongoing need for security vigilance and prompt patching of vulnerable software. Defenders should prioritize identifying and mitigating potential local privilege escalation paths within their environments, especially on systems running Ivanti Secure Access Client.

## Attack Chain

1.  The attacker gains initial local access to a system with Ivanti Secure Access Client installed through legitimate or illegitimate means.
2.  The attacker identifies a vulnerability within the Ivanti Secure Access Client software that allows for file manipulation or privilege escalation.
3.  The attacker leverages the identified vulnerability to modify critical files associated with the Ivanti Secure Access Client.
4.  Alternatively, the attacker exploits a privilege escalation vulnerability to execute commands with elevated privileges.
5.  The attacker uses the elevated privileges to install malicious software, modify system settings, or access sensitive data.
6.  The attacker leverages the compromised system to move laterally within the network, targeting other systems and resources.
7.  The attacker may establish persistent access to the compromised system, ensuring long-term control and enabling further malicious activities.

## Impact

Successful exploitation of these vulnerabilities could allow a local attacker to gain complete control over the affected system. This could lead to the compromise of sensitive data, the installation of malware, or the disruption of critical services. The number of affected systems depends on the deployment size of Ivanti Secure Access Client within an organization. This is a medium-severity vulnerability that could lead to significant impact if exploited.

## Recommendation

*   Investigate and apply any available patches or updates for Ivanti Secure Access Client to remediate the vulnerabilities.
*   Monitor process creations for unexpected child processes of the Ivanti Secure Access Client using the "Detect Suspicious Ivanti Child Processes" Sigma rule.
*   Monitor file modifications in Ivanti Secure Access Client installation directories using the "Detect Ivanti File Modifications" Sigma rule.
