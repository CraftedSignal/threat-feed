---
title: CODESYS Control Runtime Boot Application Replacement Vulnerability (CVE-2025-41660)
slug: 2024-01-codesys-boot-app-replace
description: A low-privileged remote attacker can replace the boot application of the CODESYS Control runtime system via CVE-2025-41660, leading to unauthorized code execution.
date: "2024-01-21T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - codesys
  - unauthorized-code-execution
  - cve-2025-41660
vendors:
  - CODESYS
products:
  - CODESYS Control Runtime
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-41660
  - https://certvde.com/de/advisories/VDE-2026-011
rules:
  - title: Detect CODESYS Boot Application Replacement Attempt
    description: Detects attempts to replace the CODESYS boot application by monitoring network traffic for suspicious patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - network_connection
      - windows
  - title: Detect CODESYS Unauthorized Executable Write
    description: Detects unauthorized write operations to the CODESYS executable directory, which could indicate a malicious boot application being installed.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2025-41660 describes a vulnerability in the CODESYS Control runtime system. A low-privileged remote attacker can exploit this vulnerability to replace the boot application of the CODESYS Control runtime system. This allows the attacker to execute unauthorized code on the affected system. The vulnerability has a CVSS v3.1 base score of 8.8, indicating a high severity. The vulnerability was published on 2026-03-24. This vulnerability allows for complete compromise of the affected CODESYS system, potentially disrupting industrial control processes.

## Attack Chain

1. The attacker gains low-privileged network access to the CODESYS Control runtime system.
2. The attacker exploits CVE-2025-41660 to initiate the boot application replacement process. This likely involves sending a crafted request to a specific network service exposed by the CODESYS runtime.
3. The attacker uploads a malicious boot application to the CODESYS Control runtime system.
4. The system validates (or fails to properly validate) the new boot application.
5. The CODESYS Control runtime system reboots and loads the malicious boot application.
6. The malicious boot application executes arbitrary code on the system, granting the attacker control.
7. The attacker can now manipulate industrial control processes, potentially causing damage or disruption.

## Impact

Successful exploitation of CVE-2025-41660 allows a low-privileged attacker to gain complete control over the CODESYS Control runtime system. This could lead to disruption of industrial control processes, data theft, or physical damage to equipment. The CODESYS platform is used in a wide range of industries, including manufacturing, energy, and infrastructure, so the potential impact is significant.

## Recommendation

*   Apply available patches or updates from CODESYS to address CVE-2025-41660 as soon as they are released.
*   Monitor network traffic to CODESYS Control runtime systems for suspicious activity related to boot application replacement. Consider deploying the Sigma rules below.
*   Implement network segmentation to limit access to CODESYS Control runtime systems from untrusted networks.
*   Review and enforce strong authentication and authorization policies for CODESYS Control runtime systems.
