---
title: CVE-2026-32087 Function Discovery Service Privilege Escalation
slug: 2026-04-fdwsd-privesc
description: CVE-2026-32087 is a heap-based buffer overflow vulnerability in the Function Discovery Service (fdwsd.dll) that allows an authorized local attacker to elevate privileges on a Windows system.
date: "2026-04-14T18:17:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - heap-overflow
  - cve
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32087
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32087
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32087
rules:
  - title: Detect Suspicious Process Creation from FDWSD
    description: Detects potential exploitation of CVE-2026-32087 by monitoring for unusual processes spawned by fdwsd.dll.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect FDWSD Service Anomalous Network Connection
    description: Detects potential exploitation of CVE-2026-32087 by monitoring for unusual network connections originating from fdwsd.dll.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - privilege_escalation
    techniques:
      - T1068
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32087 describes a heap-based buffer overflow vulnerability affecting the Function Discovery Service, specifically the `fdwsd.dll` module. This vulnerability allows a locally authenticated attacker with low privileges to escalate their privileges to a higher level on the targeted Windows system. The vulnerability exists within the handling of specific data structures or function calls within `fdwsd.dll`, leading to memory corruption when processing malformed input. Successful exploitation could allow an attacker to execute arbitrary code with elevated privileges, potentially leading to complete system compromise. The scope of the vulnerability is limited to local exploitation, requiring prior access to the system.

## Attack Chain

1. The attacker gains initial access to the Windows system with low-privileged credentials.
2. The attacker crafts a malicious input designed to trigger the heap-based buffer overflow within `fdwsd.dll`.
3. The attacker interacts with the Function Discovery Service, providing the crafted malicious input, potentially through a specially crafted application or API call.
4. The Function Discovery Service attempts to process the attacker-supplied input via `fdwsd.dll`.
5. During the processing, the heap-based buffer overflow occurs due to insufficient bounds checking, overwriting adjacent memory regions on the heap.
6. The attacker leverages the memory corruption to overwrite critical system data structures or inject malicious code into memory.
7. The injected code or modified data structures are then executed by the Function Discovery Service, running with elevated privileges.
8. The attacker successfully escalates their privileges and gains control over the system.

## Impact

Successful exploitation of CVE-2026-32087 leads to local privilege escalation, granting the attacker elevated privileges on the compromised system. This allows the attacker to perform actions restricted to administrators or system-level accounts, such as installing software, modifying system configurations, accessing sensitive data, or creating new accounts with elevated privileges. The impact is limited to the local system, but a successful privilege escalation is a critical step for attackers aiming to achieve lateral movement or persistence within a network.

## Recommendation

*   Apply the security update released by Microsoft to patch CVE-2026-32087, as detailed in the Microsoft Security Response Center advisory [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32087](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32087).
*   Monitor for suspicious process creations originating from the Function Discovery Service (fdwsd.dll) using process creation logs and deploy the Sigma rule `Detect Suspicious Process Creation from FDWSD` to identify potential exploitation attempts.
*   Implement strict access control policies to limit local access to systems and reduce the attack surface for this vulnerability.
