---
title: Windows SSDP Service Race Condition Privilege Escalation (CVE-2026-32068)
slug: 2026-04-ssdp-privesc
description: CVE-2026-32068 is a race condition vulnerability in the Windows SSDP Service that allows an authorized attacker to elevate privileges locally.
date: "2026-04-15T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - cve-2026-32068
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32068
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32068
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32068
rules:
  - title: Detect SSDP Service Hosting Svchost with Anomalous Child Processes
    description: Detects unusual child processes spawned from the svchost.exe process hosting the SSDP service, which could indicate exploitation attempts related to CVE-2026-32068.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect SSDP Service Svchost with Modified CommandLine
    description: Detects changes to the command line of the svchost.exe process hosting the SSDP service, potentially indicating an attempt to exploit CVE-2026-32068.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32068 describes a race condition vulnerability within the Windows SSDP (Simple Service Discovery Protocol) service. This vulnerability allows a locally authenticated attacker with low privileges to potentially escalate their privileges to SYSTEM. The vulnerability stems from improper synchronization when the SSDP service handles concurrent requests. Exploitation requires careful timing to manipulate shared resources. While the vulnerability was published on 2026-04-14, active exploitation in the wild has not been reported. Successful exploitation could lead to complete system compromise.

## Attack Chain

1. The attacker authenticates to the target Windows system with low privileges.
2. The attacker crafts a malicious SSDP request designed to trigger the race condition.
3. The attacker sends the malicious SSDP request to the SSDP service (svchost.exe -k LocalServiceNetworkRestricted).
4. The SSDP service attempts to process the malicious request concurrently with another legitimate or malicious request.
5. Due to the race condition, the service's internal state becomes corrupted because of unsynchronized access to shared resources.
6. The corrupted state allows the attacker to overwrite critical system data or execute arbitrary code within the context of the SSDP service (NT AUTHORITY\LocalService).
7. The attacker gains elevated privileges (SYSTEM) on the local machine.

## Impact

Successful exploitation of CVE-2026-32068 allows an attacker with local access to escalate their privileges to SYSTEM. This grants the attacker full control over the compromised system, enabling them to install software, modify data, create new accounts, and potentially use the system as a pivot point to attack other systems on the network. The impact is significant due to the widespread deployment of Windows systems.

## Recommendation

*   Monitor for unusual process creation events originating from the `svchost.exe` process hosting the SSDP service (`svchost.exe -k LocalServiceNetworkRestricted`) using the provided Sigma rule.
*   Deploy the Sigma rules to detect anomalous process arguments to `svchost.exe` related to the SSDP service, and tune for your environment.
*   Implement strict access control policies to limit local user privileges, reducing the potential impact of successful privilege escalation.
