---
title: Potential Adobe Hijack Persistence Mechanism
slug: 2024-01-adobe-hijack
description: This brief outlines a potential persistence mechanism involving hijacking Adobe-related processes or components, which could allow attackers to maintain unauthorized access to a system.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - process-injection
  - adobe
vendors:
  - Adobe
products:
  - Adobe Acrobat Reader
  - Adobe
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_adobe_hijack_persistence.toml
rules:
  - title: Detect Suspicious Adobe Process Modification
    description: Detects modification of Adobe-related executable files which could indicate a process hijacking attempt.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Registry Modification in Adobe Directory
    description: Detects registry modifications pointing to unusual executables within Adobe installation directories, indicating potential hijacking.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This brief discusses a potential persistence technique involving the hijacking of Adobe-related processes or components. While specific details of observed campaigns are unavailable, this technique exploits the trust associated with legitimate Adobe software to maintain a foothold on a compromised system. By replacing or modifying Adobe binaries or libraries with malicious versions, attackers can ensure their code is executed whenever the legitimate Adobe software is launched. This approach allows malware to evade detection by blending in with trusted processes and potentially bypassing security measures that are configured to allow Adobe software to run unhindered. Given the widespread use of Adobe products, this presents a significant risk to a broad range of systems.

## Attack Chain

1.  Initial access is gained through an unknown method (e.g., exploiting a vulnerability in a different application, or social engineering).
2.  The attacker identifies a suitable Adobe process or component to hijack (e.g., AcroRd32.exe, AdobeUpdate.exe).
3.  The attacker replaces the legitimate Adobe binary with a malicious executable or modifies an existing Adobe DLL to inject malicious code.
4.  The attacker establishes persistence by ensuring the modified Adobe component is launched automatically upon system startup or user login (e.g., via registry keys, scheduled tasks, or startup folders).
5.  When the user or system launches the legitimate Adobe application, the malicious code is executed, providing the attacker with control.
6.  The attacker uses the compromised process to perform malicious activities such as downloading additional payloads, exfiltrating data, or establishing command and control.
7.  The attacker attempts to maintain stealth by masquerading as a legitimate Adobe process and avoiding detection by security tools.

## Impact

Successful exploitation of this technique could allow attackers to maintain long-term, persistent access to a compromised system. This could result in data theft, system compromise, and potential disruption of business operations. Due to the trusted nature of Adobe applications, this technique can be difficult to detect and remediate, potentially affecting a large number of users and organizations across various sectors.
