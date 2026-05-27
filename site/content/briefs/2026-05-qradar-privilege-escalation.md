---
title: IBM QRadar Vulnerability CVE-2024-56462 Allows Privilege Escalation via Malicious Backup Upload
slug: 2026-05-qradar-privilege-escalation
description: IBM QRadar 7.5.0 through 7.5.0 UP15 Interim Fix 002 is vulnerable to CVE-2024-56462, enabling a privileged user to upload a malicious backup archive that, upon restoration, leads to unauthorized access to the underlying operating system.
date: "2026-05-27T14:18:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - cve
  - ibm
vendors:
  - IBM
products:
  - QRadar 7.5.0
  - QRadar 7.5.0 UP15 Interim Fix 002
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2024-56462
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-56462
  - https://www.ibm.com/support/pages/node/7273957
rules:
  - title: Detect Suspicious QRadar Backup Upload
    description: Detects CVE-2024-56462 exploitation — Identifies attempts to upload potentially malicious backup archives to QRadar
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect QRadar Restore Operation with Unusual Files
    description: Detects CVE-2024-56462 exploitation — Detects the execution of files with suspicious file extensions within QRadar restore directories, potentially indicating exploitation.
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

CVE-2024-56462 affects IBM QRadar versions 7.5.0 through 7.5.0 UP15 Interim Fix 002. This vulnerability allows a user with elevated privileges within the QRadar application to upload a specially crafted, malicious backup archive. Upon restoring this compromised backup, an attacker can gain unauthorized access to the underlying operating system hosting the QRadar instance. This can lead to a complete compromise of the QRadar system and potentially the wider network it monitors. Defenders should prioritize patching and monitoring for suspicious backup activity to prevent exploitation.

## Attack Chain

1. An attacker gains initial privileged access to the QRadar web interface.
2. The attacker crafts a malicious backup archive containing altered system files or scripts.
3. The privileged attacker uploads the malicious backup archive through the QRadar backup/restore functionality.
4. The attacker initiates a restore operation using the uploaded malicious backup archive.
5. During the restoration process, the malicious files overwrite legitimate system files.
6. A scheduled task or system service executes the replaced malicious files.
7. The attacker gains remote access to the underlying operating system with elevated privileges.
8. The attacker can perform lateral movement, data exfiltration, or other malicious activities.

## Impact

Successful exploitation of CVE-2024-56462 allows a privileged user to escalate their privileges to the operating system level on the QRadar appliance. This could lead to complete compromise of the QRadar instance and the sensitive security data it manages. The attacker can then pivot to other systems on the network, potentially impacting numerous systems. Given QRadar's role in security monitoring, a successful attack can blind the organization to other ongoing threats.

## Recommendation

*   Apply the latest patches and interim fixes for IBM QRadar to address CVE-2024-56462.
*   Monitor QRadar logs for unusual activity related to backup and restore operations, specifically uploads from unexpected sources and subsequent restore jobs.
*   Implement strict access control policies for the QRadar web interface to limit who can upload and restore backups.
*   Deploy the Sigma rule "Detect Suspicious QRadar Backup Upload" to identify suspicious backup uploads based on file extension or content.
*   Regularly review QRadar user privileges and remove any unnecessary access rights to minimize the attack surface.
*   Enable audit logging on the underlying operating system to detect unauthorized file modifications or process executions following a restore operation.
