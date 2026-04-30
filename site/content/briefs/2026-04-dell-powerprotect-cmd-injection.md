---
title: Dell PowerProtect Data Domain Command Injection Vulnerability (CVE-2026-23778)
slug: 2026-04-dell-powerprotect-cmd-injection
description: A command injection vulnerability in Dell PowerProtect Data Domain (CVE-2026-23778) could allow a remote, high-privileged attacker to gain root-level access.
date: "2026-04-17T09:16:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-23778
  - command-injection
  - dell
  - powerprotect
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-23778
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23778
  - https://www.dell.com/support/kbdoc/en-us/000450699/dsa-2026-060-security-update-for-dell-powerprotect-data-domain-multiple-vulnerabilities
iocs:
  - type: url
    value: https://www.dell.com/support/kbdoc/en-us/000450699/dsa-2026-060-security-update-for-dell-powerprotect-data-domain-multiple-vulnerabilities
ioc_counts:
  url: 1
rules:
  - title: Detect Web Requests to Dell PowerProtect Systems
    description: Detects HTTP requests to Dell PowerProtect systems, which can be used to detect exploitation attempts.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Command Injection Attempts in Web Requests
    description: Detects common command injection attempts within HTTP requests, which could indicate exploitation of CVE-2026-23778.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-23778 is a command injection vulnerability affecting Dell PowerProtect Data Domain appliances running Data Domain Operating System (DD OS). The affected versions include Feature Release versions 7.7.1.0 through 8.5, LTS2025 release version 8.3.1.0 through 8.3.1.20, and LTS2024 release versions 7.13.1.0 through 7.13.1.50. A remote attacker with high privileges could exploit this vulnerability to execute arbitrary commands with root privileges on the affected system. Successful exploitation would grant the attacker complete control over the Data Domain appliance, potentially leading to data loss, system compromise, and disruption of backup and recovery operations. Due to the critical role of Data Domain appliances in data protection, this vulnerability poses a significant risk to organizations using affected versions.

## Attack Chain

1.  The attacker gains high-privileged remote access to the Dell PowerProtect Data Domain appliance, likely through compromised credentials or a separate vulnerability.
2.  The attacker crafts a malicious HTTP request containing a command injection payload targeting a vulnerable endpoint within the DD OS web management interface.
3.  The vulnerable endpoint fails to properly sanitize user-supplied input, allowing the attacker to inject arbitrary operating system commands into the system.
4.  The injected command is executed with the privileges of the webserver process, which in this case, runs with root privileges.
5.  The attacker leverages the initial command execution to establish persistence on the system, such as creating a new user account or modifying system configuration files.
6.  The attacker uses the gained root access to move laterally within the Data Domain appliance, potentially accessing sensitive data or compromising other services.
7.  The attacker could exfiltrate sensitive data, deploy ransomware, or disrupt backup operations depending on their objectives.

## Impact

Successful exploitation of CVE-2026-23778 grants a remote attacker complete control over the Dell PowerProtect Data Domain appliance. This can lead to severe consequences, including unauthorized access to sensitive data, data corruption, disruption of backup and recovery processes, and potential ransomware deployment. Given the Data Domain's central role in data protection strategies, a successful attack can have a widespread impact, affecting numerous systems and applications that rely on the backup infrastructure.

## Recommendation

*   Apply the security update provided by Dell to patch CVE-2026-23778. Refer to the Dell security advisory for specific instructions: [https://www.dell.com/support/kbdoc/en-us/000450699/dsa-2026-060-security-update-for-dell-powerprotect-data-domain-multiple-vulnerabilities](https://www.dell.com/support/kbdoc/en-us/000450699/dsa-2026-060-security-update-for-dell-powerprotect-data-domain-multiple-vulnerabilities).
*   Implement network segmentation to limit the blast radius of a potential compromise. Restrict network access to the Dell PowerProtect Data Domain appliance to only authorized users and systems.
*   Review user access controls and enforce the principle of least privilege. Ensure that users only have the necessary permissions to perform their job functions on the Data Domain appliance.
