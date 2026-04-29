---
title: Balena Etcher for Windows TOCTOU Vulnerability
slug: 2026-04-balena-etcher-toctou
description: A Time-of-Check to Time-of-Use (TOCTOU) race condition vulnerability in Balena Etcher for Windows prior to v2.1.4 allows attackers to escalate privileges and execute arbitrary code by replacing a legitimate script with a crafted payload during the flashing process.
date: "2026-04-02T16:16:22Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - privilege-escalation
  - toctou
  - balena-etcher
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-30332
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-30332
  - https://github.com/B1tBreaker/CVE-2026-30332
  - https://github.com/balena-io/etcher/issues/4500
  - https://www.balena.io/security
rules:
  - title: Detect Suspicious Balena Etcher Child Processes
    description: Detects suspicious child processes spawned by Balena Etcher, indicating potential privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect File Replacement in Balena Etcher Directory
    description: Detects file creation events in Balena Etcher directory indicating potential TOCTOU exploit
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Balena Etcher for Windows versions prior to 2.1.4 are susceptible to a Time-of-Check to Time-of-Use (TOCTOU) race condition vulnerability (CVE-2026-30332). This flaw arises during the flashing process where a legitimate script can be replaced with a malicious payload. An attacker with local access and the ability to influence the file system can exploit this vulnerability to escalate privileges and execute arbitrary code. The successful exploitation of this issue can lead to a complete compromise of the affected system, granting the attacker full control. This is particularly concerning for environments where users with limited privileges routinely use Balena Etcher.

## Attack Chain

1.  Attacker gains initial local access to a Windows system where Balena Etcher is installed (versions prior to 2.1.4).
2.  The attacker identifies a legitimate script used by Balena Etcher during the flashing process.
3.  The attacker monitors the file system for Balena Etcher to access the targeted legitimate script.
4.  Before Etcher uses the legitimate script, the attacker leverages the TOCTOU vulnerability by rapidly replacing the legitimate script with a malicious script of the same name.
5.  Balena Etcher, still operating under elevated privileges due to its intended function, executes the attacker-controlled script.
6.  The malicious script performs actions to escalate privileges.
7.  The attacker executes arbitrary code within the context of the elevated privileges.
8.  The attacker achieves persistence and control over the compromised system.

## Impact

Successful exploitation of CVE-2026-30332 allows an attacker to escalate privileges on a Windows system running a vulnerable version of Balena Etcher. This can lead to the execution of arbitrary code, potentially resulting in data theft, system compromise, or denial of service. The vulnerability affects versions prior to 2.1.4, and if left unpatched, could lead to widespread exploitation in environments where Balena Etcher is commonly used.

## Recommendation

*   Upgrade Balena Etcher to version 2.1.4 or later to patch the vulnerability (CVE-2026-30332).
*   Implement file integrity monitoring on the Balena Etcher installation directory to detect unauthorized modifications to script files.
*   Monitor process creation events for unexpected processes spawned by Balena Etcher to identify potential exploitation attempts. Deploy the Sigma rule `Detect Suspicious Balena Etcher Child Processes` to your SIEM.
