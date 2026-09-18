---
title: Detection of SUID/SGID Bit Modification for Privilege Escalation
slug: 2026-09-suid-sgid-abuse
description: Adversaries may use chmod or install to set SUID or SGID bits on files, allowing malicious code to execute with elevated privileges for persistence or escalation.
date: "2026-09-18T19:24:07Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - privilege-escalation
  - persistence
  - defense-evasion
  - linux
  - macos
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: An adversary may add the setuid or setgid bit to a file or directory in order to run a file with the privileges of the owning user or group.
    confidence_band: high
references:
  - https://www.elastic.co/security-labs/primer-on-persistence-mechanisms
  - https://attack.mitre.org/techniques/T1548/001/
rules:
  - title: Detect SUID/SGID Bit Set via chmod or install
    description: Detects the use of chmod or install to set SUID or SGID bits, which can be used for privilege escalation.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1548.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the detection rule for SUID/SGID modifications
      owner: Detection Engineering
      due: 48h
      evidence: Source provides concrete process arguments for detection
  mitigation_plan:
    - priority: medium_term
      action: Audit existing SUID/SGID binaries for unnecessary elevated permissions
      owner: IT Operations
      addresses: T1548.001
      evidence: Reducing the attack surface limits privilege escalation impact
---

Adversaries targeting Unix-like systems, including Linux and macOS, often abuse SUID (Set Owner User ID) and SGID (Set Group ID) bits to achieve privilege escalation or persistence. By setting these bits on a binary or script, an attacker ensures the file executes with the permissions of the file owner or group rather than the user invoking the file. This technique allows attackers to bypass standard access controls, exploit vulnerabilities in setuid applications, or execute their own malware in an elevated context. This activity is typically performed using command-line utilities such as chmod or install. Monitoring the execution of these utilities with flags that modify SUID/SGID bits is essential for detecting unauthorized privilege escalation attempts.

## Impact

Successful abuse of SUID/SGID bits allows unauthorized users to gain elevated access, potentially leading to full system compromise. If an attacker gains the ability to execute code as root or a high-privileged service user, they can bypass security restrictions, exfiltrate sensitive data, or establish long-term persistence that survives system reboots and user session termination.

## Recommendation

Detection engineering teams should monitor for the unauthorized use of chmod and install commands to set SUID/SGID bits.
- Implement the provided Sigma rule to alert on suspicious chmod/install command arguments.
- Establish a baseline of legitimate SUID/SGID modifications performed by automated package managers or deployment scripts to reduce noise.
- Audit file systems for unexpected files with the SUID or SGID bits set, particularly in directories writable by non-privileged users.
- Correlate chmod events with other suspicious activity from the same user or process hierarchy to identify malicious intent versus administrative maintenance.
