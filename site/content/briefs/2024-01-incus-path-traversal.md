---
title: Incus Path Traversal Vulnerability (CVE-2026-33945)
slug: 2024-01-incus-path-traversal
description: A path traversal vulnerability in Incus versions prior to 6.23.0 (CVE-2026-33945) allows an attacker to write arbitrary files as root, leading to privilege escalation and denial of service by crafting a malicious systemd credential path.
date: "2024-01-28T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - incus
  - path-traversal
  - privilege-escalation
  - denial-of-service
  - CVE-2026-33945
  - linux
vendors:
  - Incus
products:
  - Incus
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33945
rules:
  - title: Detect Suspicious File Modification via Incus Exploit
    description: Detects suspicious file modifications in sensitive directories, potentially indicating exploitation of CVE-2026-33945.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-33945
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect Incus Configuration Changes with Path Traversal
    description: Detects modifications to Incus configuration files that contain potential path traversal attempts.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-33945
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Incus, a system container and virtual machine manager, is susceptible to a critical vulnerability (CVE-2026-33945) affecting versions prior to 6.23.0. The vulnerability resides in the handling of systemd credentials passed to guest containers. An attacker can exploit this by crafting a configuration key (e.g., `systemd.credential.../../../../../../root/.bashrc`) containing path traversal sequences, causing Incus to write outside the intended `credentials` directory. This occurs because Incus insufficiently validates the `systemd.credential.XYZ` syntax, allowing the `XYZ` portion to include periods and traverse the filesystem. While direct data reading is prevented, the ability to write arbitrary files as root grants attackers privilege escalation and denial-of-service capabilities. Users should upgrade to version 6.23.0 or later to mitigate this risk.

## Attack Chain

1. Attacker identifies an Incus instance running a version prior to 6.23.0.
2. The attacker gains access to the Incus instance, potentially through existing vulnerabilities or compromised credentials.
3. Attacker crafts a malicious configuration key using the `systemd.credential.XYZ` syntax, embedding path traversal sequences (e.g., `systemd.credential.../../../../../../root/.bashrc`).
4. The attacker sets the crafted configuration key within the Incus instance's configuration.
5. Incus attempts to write the systemd credential data to the specified path, which, due to the path traversal, resolves to an arbitrary location on the host filesystem.
6. The attacker overwrites a critical system file (e.g., `.bashrc`, `/etc/passwd`) with malicious content, leveraging root privileges.
7. The attacker triggers the execution of the overwritten file (e.g., by logging in as root, starting a new shell, or restarting a service).
8. The attacker gains escalated privileges or causes a denial of service.

## Impact

Successful exploitation of CVE-2026-33945 allows attackers to gain root privileges on the Incus host system. This can lead to complete system compromise, including data theft, modification, or destruction. Furthermore, attackers can leverage this vulnerability to cause a denial of service by overwriting critical system files. The severity is high due to the ease of exploitation and the potential for significant impact on affected systems. While there is no public report on the number of victims, any organization using vulnerable versions of Incus is potentially at risk.

## Recommendation

*   Upgrade Incus to version 6.23.0 or later to patch CVE-2026-33945.
*   Implement filesystem monitoring for unexpected writes to sensitive system directories (e.g., `/root`, `/etc`) to detect potential exploitation attempts. Deploy the provided Sigma rule to detect suspicious file modifications.
*   Enable audit logging on Incus configuration files to monitor for unauthorized changes. Deploy the provided Sigma rule to detect unauthorized changes to incus configuration files.
