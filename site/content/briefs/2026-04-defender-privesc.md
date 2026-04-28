---
title: Microsoft Defender Privilege Escalation Vulnerability (CVE-2026-33825)
slug: 2026-04-defender-privesc
description: CVE-2026-33825 allows a locally authenticated attacker to escalate privileges in Microsoft Defender due to insufficient access control granularity.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - privilege-escalation
  - microsoft-defender
  - cve-2026-33825
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-33825
    cvss: 7.8
    epss: 0.03818
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33825
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33825
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: Suspicious Process Spawned by Microsoft Defender
    description: Detects suspicious processes spawned by Microsoft Defender processes, potentially indicating privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Defender Configuration Modification via Command Line
    description: Detects command-line modifications to Defender's configuration, potentially indicative of exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-33825 describes a privilege escalation vulnerability affecting Microsoft Defender. The vulnerability stems from insufficient granularity of access control, allowing an attacker with local access and some level of authorization to elevate their privileges on the system. The vulnerability was published on April 14, 2026. Successful exploitation of this vulnerability would allow an attacker to perform actions with higher privileges than intended, potentially leading to system compromise. Microsoft has released a patch, and defenders should apply it as soon as possible.

## Attack Chain

1.  Attacker gains initial local access to a system with Microsoft Defender installed. This may be achieved through existing credentials or exploitation of another vulnerability.
2.  The attacker identifies a specific area within Microsoft Defender where access control is insufficiently granular.
3.  The attacker crafts a malicious request or input that exploits the identified access control weakness.
4.  Microsoft Defender processes the malicious request, failing to properly validate the attacker's authorization level.
5.  The attacker gains elevated privileges within the context of Microsoft Defender.
6.  The attacker leverages the elevated privileges to modify Defender settings, policies, or configurations.
7.  The attacker uses the modified Defender configuration to execute arbitrary code with elevated privileges on the system.
8.  The attacker achieves full system compromise, potentially leading to data theft, malware installation, or denial of service.

## Impact

Successful exploitation of CVE-2026-33825 allows an attacker to escalate privileges on a system running Microsoft Defender. This could allow the attacker to disable security features, install malware, steal sensitive data, or gain complete control of the affected system. Given the widespread deployment of Microsoft Defender, this vulnerability poses a significant risk to a large number of organizations and individuals.

## Recommendation

*   Apply the Microsoft patch for CVE-2026-33825 immediately to remediate the vulnerability (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33825).
*   Monitor process creation events for unusual processes spawned by Microsoft Defender processes (see Sigma rule below).
*   Review and harden Microsoft Defender's configuration to ensure least privilege and prevent unauthorized modifications.
