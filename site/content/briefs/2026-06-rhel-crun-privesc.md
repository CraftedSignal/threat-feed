---
title: Red Hat Enterprise Linux (crun) Privilege Escalation Vulnerability
slug: 2026-06-rhel-crun-privesc
description: A local attacker can exploit a vulnerability in Red Hat Enterprise Linux (crun) to escalate their privileges, potentially gaining root access.
date: "2026-06-01T07:25:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - linux
vendors:
  - Red Hat
products:
  - crun
affected_os:
  - RHEL
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0966
rules:
  - title: Detect Suspicious crun Execution with Modified Capabilities
    description: Detects suspicious execution of crun where capabilities have been modified, which might indicate privilege escalation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect crun Execution from Suspicious Locations
    description: Detects execution of crun from unusual locations outside the standard system paths, potentially indicating a malicious or tampered binary.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability exists within the crun package in Red Hat Enterprise Linux that could allow a local attacker to escalate their privileges on the system. While the specific technical details of the vulnerability are not provided, successful exploitation would grant elevated permissions, potentially up to root. This vulnerability impacts systems where crun is installed and accessible to local users. It is crucial to investigate the affected versions and apply the necessary patches to mitigate the risk of unauthorized privilege escalation.

## Attack Chain

1.  Attacker gains initial access to the target RHEL system with limited user privileges.
2.  Attacker identifies the vulnerable version of `crun` installed on the system.
3.  Attacker crafts a malicious input or utilizes an exploit specific to the identified `crun` vulnerability.
4.  Attacker executes the malicious input/exploit using `crun`.
5.  The vulnerable `crun` binary processes the malicious input, triggering the privilege escalation.
6.  The attacker's process now runs with elevated privileges (e.g., root).
7.  Attacker leverages the elevated privileges to perform unauthorized actions, such as installing malware, modifying system configurations, or accessing sensitive data.

## Impact

Successful exploitation of this vulnerability allows a local attacker to gain elevated privileges on the affected system. This can lead to complete system compromise, including unauthorized access to sensitive data, modification of system configurations, and installation of malicious software. The impact is significant for systems handling sensitive information or critical infrastructure components.

## Recommendation

*   Investigate the `crun` version installed on all RHEL systems and compare them to Red Hat's security advisories for known vulnerable versions.
*   Apply the necessary patches provided by Red Hat to remediate the vulnerability in `crun`.
*   Monitor process execution for unexpected or unauthorized use of the `crun` binary, as highlighted in the Sigma rules below.
