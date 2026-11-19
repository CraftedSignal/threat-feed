---
brief_id: brief-2026-05-defender-vulns
event_id: brief-2026-05-defender-vulns
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:3612abe3c323b2ac3d5b73cb382200d63d34afa06020465628be1686b7ba2e58
    summary: exploited:true; KEV CVE-2026-41091
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Multiple Vulnerabilities in Microsoft Defender and Malware Protection Engine
slug: 2026-05-defender-vulns
description: Multiple vulnerabilities in Microsoft Defender and Microsoft Malware Protection Engine could allow an attacker to elevate privileges, execute arbitrary code, and cause a denial of service condition.
date: "2026-05-20T11:02:30Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-05-20T00:00:00Z"
  confidence: high
tags:
  - privilege-escalation
  - execution
  - impact
  - windows
vendors:
  - Microsoft
products:
  - Defender
  - Malware Protection Engine
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-41091
    cvss: 7.8
    kev: true
    kev_status: "true"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1603
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41091
rules:
  - title: Detect Suspicious Process Creation by MsMpEng.exe
    description: Detects unusual processes spawned by Microsoft Defender's MsMpEng.exe, potentially indicating privilege escalation or code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect MsMpEng.exe Writing Executables
    description: Detects Microsoft Defender's MsMpEng.exe writing executable files, which is not typical behavior and could indicate exploitation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - file_event
      - windows
rules_count: 2
updates:
  - at: "2026-05-20T13:19:10Z"
    level: L2
    summary: added CVE-2026-41091
    sources:
      - nvd
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-41091
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Microsoft Defender and the Microsoft Malware Protection Engine are affected by multiple vulnerabilities that could allow an attacker to perform several malicious actions. These include elevating privileges on a target system, achieving arbitrary code execution, and causing a denial of service (DoS) condition. The vulnerabilities exist within the core components of Microsoft's endpoint security solution, making exploitation a significant risk for affected systems. Successful exploitation of these vulnerabilities would grant attackers significant control over the compromised system, allowing for further malicious activities.

## Attack Chain

1. An attacker exploits a vulnerability in the Microsoft Malware Protection Engine via a specially crafted file.
2. The vulnerable engine processes the file, triggering a memory corruption issue.
3. This memory corruption allows the attacker to overwrite critical system data.
4. The attacker leverages the overwritten data to elevate their privileges to SYSTEM.
5. With elevated privileges, the attacker injects malicious code into a legitimate system process.
6. The injected code executes arbitrary commands, providing the attacker with control over the system.
7. Alternatively, the attacker triggers a denial-of-service condition by causing the engine to crash repeatedly.

## Impact

Successful exploitation of these vulnerabilities could lead to complete system compromise. An attacker could gain full control of the system, potentially leading to data theft, installation of malware, or disruption of services. The lack of specific victim numbers in the source material makes a definitive impact assessment difficult; however, given the widespread use of Microsoft Defender, a successful widespread exploit would have substantial impact across numerous sectors.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect exploitation attempts.
*   Monitor process creation events for unusual processes spawned by Microsoft Defender processes (e.g., `MsMpEng.exe`) using the provided Sigma rule.
*   Enable Sysmon process-creation logging to activate the rules above.
