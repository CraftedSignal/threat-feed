---
title: Windows UPnP Service Local Privilege Escalation via CVE-2026-32077
slug: 2026-04-upnp-privesc
description: CVE-2026-32077 is an untrusted pointer dereference vulnerability in the Windows Universal Plug and Play (UPnP) Device Host service that allows a locally authenticated attacker to escalate privileges.
date: "2026-04-14T18:35:17Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - upnp
  - cve-2026-32077
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32077
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32077
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32077
rules:
  - title: Suspicious Process Creation from UPnP Host
    description: Detects suspicious process creation events originating from the UPnP Device Host service, potentially indicating exploitation of CVE-2026-32077.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: UPnP Host Spawning Unusual Network Connections
    description: Detects network connections initiated by the UPnP Device Host service to unusual ports or IPs, indicative of potential compromise following CVE-2026-32077 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32077 is a critical vulnerability affecting the Windows Universal Plug and Play (UPnP) Device Host service. This vulnerability stems from an untrusted pointer dereference within the UPnP service, potentially allowing an attacker with local access to escalate their privileges. Successful exploitation would grant the attacker elevated permissions, potentially leading to complete system compromise. Microsoft patched this vulnerability as part of their April 2026 security update. Given the widespread use of UPnP for network device discovery and configuration, this vulnerability poses a significant risk to Windows systems within both home and enterprise environments.

## Attack Chain

1. The attacker gains local access to the target Windows system.
2. The attacker crafts a malicious UPnP service request.
3. The attacker sends the crafted request to the UPnP Device Host service (upnphost.dll).
4. The UPnP service improperly processes the malicious request, leading to an untrusted pointer dereference.
5. The attacker leverages the pointer dereference to overwrite critical system memory.
6. The attacker injects malicious code into the UPnP service process.
7. The injected code executes with the privileges of the UPnP service, typically SYSTEM.
8. The attacker achieves local privilege escalation and can perform administrative actions on the system.

## Impact

Successful exploitation of CVE-2026-32077 allows a local attacker to elevate their privileges to SYSTEM. This could allow the attacker to install programs, view, change, or delete data, or create new accounts with full user rights. While the vulnerability requires local access, its ease of exploitation and the prevalence of UPnP make it a high-risk issue. An attacker could leverage other vulnerabilities or social engineering techniques to gain initial local access, then use CVE-2026-32077 to escalate privileges and gain complete control of the compromised system.

## Recommendation

*   Apply the Microsoft security update released in April 2026 to patch CVE-2026-32077 on all Windows systems.
*   Monitor for suspicious process creation events originating from the `upnphost.dll` service using the provided Sigma rule.
*   Consider disabling the UPnP service if it is not required, especially on systems with high security requirements.
*   Enable Sysmon process-creation logging to enhance visibility into process execution and parent-child relationships for the provided Sigma rules.
