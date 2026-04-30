---
title: Lakeside SysTrack Agent Local Privilege Escalation via Race Condition (CVE-2026-35099)
slug: 2026-04-lakeside-systrack-lpe
description: Lakeside SysTrack Agent 11 before 11.2.1.28 is vulnerable to a race condition that allows for local privilege escalation to SYSTEM, as tracked by CVE-2026-35099.
date: "2026-04-01T16:23:50Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - lakeside
  - systrack
  - privilege-escalation
  - race-condition
  - cve-2026-35099
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35099
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35099
  - https://documentation.lakesidesoftware.com/en/Content/Release%20Notes/Agent/11.2.1.28%20Hotfix%20Agent%20Release%20Notes.htm?tocpath=Release%20Notes%7CAgent%7C_____8
rules:
  - title: Detect Suspicious SysTrack Agent Process Creation
    description: Detects potential exploitation of Lakeside SysTrack Agent by monitoring for suspicious process creations initiated by the agent.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1543.003
    data_sources:
      - process_creation
      - windows
  - title: Detect SysTrack Agent Writing Executables
    description: Detects the SysTrack Agent writing executable files, potentially indicating a privilege escalation attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1543.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Lakeside SysTrack Agent, a system monitoring tool, contains a local privilege escalation vulnerability. Specifically, versions of Agent 11 prior to 11.2.1.28 are susceptible to a race condition (CWE-362) that can be exploited by a local attacker to gain SYSTEM privileges. This vulnerability, identified as CVE-2026-35099, allows an attacker with limited privileges to execute arbitrary code with the highest level of permissions on the system. Successful exploitation could lead to complete system compromise, data theft, and other malicious activities. Organizations using vulnerable versions of the SysTrack Agent should upgrade to the patched version (11.2.1.28) as soon as possible.

## Attack Chain

1.  The attacker gains initial local access to the target system, possibly through phishing or social engineering.
2.  The attacker identifies the presence of a vulnerable Lakeside SysTrack Agent version (prior to 11.2.1.28).
3.  The attacker crafts a malicious executable or script designed to trigger the race condition within the SysTrack Agent.
4.  The attacker executes the malicious code, which attempts to manipulate shared resources concurrently with the SysTrack Agent.
5.  The race condition is successfully triggered, allowing the attacker to overwrite critical system files or inject malicious code into the SysTrack Agent's process.
6.  Due to the race condition, the SysTrack Agent executes the attacker's injected code with SYSTEM privileges.
7.  The attacker leverages SYSTEM privileges to install a backdoor, create new administrative accounts, or perform other malicious activities.
8.  The attacker achieves persistent SYSTEM-level access, enabling them to control the compromised system remotely.

## Impact

Successful exploitation of CVE-2026-35099 allows an attacker to escalate privileges from a normal user to SYSTEM on a vulnerable Windows system. This gives the attacker complete control over the system, potentially leading to data breaches, malware installation, or denial of service. Given the nature of system monitoring agents, a successful compromise can provide deep insights into the organization's environment.

## Recommendation

*   Upgrade Lakeside SysTrack Agent to version 11.2.1.28 or later to remediate CVE-2026-35099, as mentioned in the Lakeside documentation ([https://documentation.lakesidesoftware.com/en/Content/Release%20Notes/Agent/11.2.1.28%20Hotfix%20Agent%20Release%20Notes.htm?tocpath=Release%20Notes%7CAgent%7C_____8](https://documentation.lakesidesoftware.com/en/Content/Release%20Notes/Agent/11.2.1.28%20Hotfix%20Agent%20Release%20Notes.htm?tocpath=Release%20Notes%7CAgent%7C_____8)).
*   Implement the provided Sigma rule to detect potential exploitation attempts by monitoring for suspicious process creation events associated with SysTrack Agent.
*   Monitor for unexpected file modifications or registry changes performed by the SysTrack Agent process, which could indicate successful exploitation of the race condition.
