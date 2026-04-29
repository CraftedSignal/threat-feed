---
title: AIRBUS PSS TETRA Connectivity Server Privilege Escalation via Incorrect Permissions
slug: 2026-04-airbus-tetra-privesc
description: AIRBUS PSS TETRA Connectivity Server version 7.0 on Windows Server is vulnerable to incorrect default permissions, allowing local privilege escalation to SYSTEM by placing a malicious file in a specific directory.
date: "2026-04-03T08:16:17Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2025-7024
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2025-7024
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-7024
rules:
  - title: Detect Suspicious File Creation in Vulnerable Directory
    description: Detects the creation of new files in directories associated with AIRBUS PSS TETRA Connectivity Server, indicating potential exploitation of CVE-2025-7024.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
  - title: Detect Executables Started from Unusual Locations
    description: This rule detects processes being executed from unusual directories which might indicate an exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

AIRBUS PSS TETRA Connectivity Server version 7.0 running on Windows Server operating systems is susceptible to a privilege escalation vulnerability (CVE-2025-7024) due to incorrect default permissions. An attacker, with low privileges, can exploit this vulnerability to execute arbitrary code with SYSTEM privileges. The attack requires a user to be tricked or directed into placing a crafted file into a specific, vulnerable directory within the TETRA Connectivity Server installation. A fix is available and has been delivered to impacted customers. This vulnerability poses a significant risk to organizations using the affected software, as successful exploitation could lead to complete system compromise.

## Attack Chain

1.  Attacker gains initial low-privilege access to the Windows Server system.
2.  Attacker identifies the vulnerable directory within the AIRBUS PSS TETRA Connectivity Server 7.0 installation due to incorrect default permissions.
3.  Attacker crafts a malicious executable or script designed to execute arbitrary commands.
4.  Attacker social engineers or tricks a legitimate user with write access to the vulnerable directory into placing the crafted malicious file into the directory.
5.  The system or a service running under a higher privilege (e.g., SYSTEM) attempts to execute or process the malicious file placed in the vulnerable directory.
6.  The malicious code executes with the privileges of the process that initiated it (SYSTEM).
7.  Attacker leverages SYSTEM privileges to install malware, create new accounts, or modify system configurations.
8.  Attacker achieves complete control over the compromised Windows Server system.

## Impact

Successful exploitation of CVE-2025-7024 allows a low-privileged attacker to gain SYSTEM-level privileges on a Windows Server system running AIRBUS PSS TETRA Connectivity Server 7.0. This could lead to complete system compromise, data breaches, and disruption of services. The impact is critical for organizations relying on this server for their operations, as it can result in significant financial losses, reputational damage, and legal liabilities. Although the number of victims is unknown, the vulnerable software is used in critical infrastructure sectors, amplifying the potential impact.

## Recommendation

*   Apply the patch provided by AIRBUS to address CVE-2025-7024 on all systems running TETRA Connectivity Server 7.0.
*   Implement the Sigma rule "Detect Suspicious File Creation in Vulnerable Directory" to monitor for unauthorized file creation in directories associated with TETRA Connectivity Server.
*   Enforce strict file and directory permission policies on Windows Server systems to prevent unauthorized write access to sensitive directories, mitigating the underlying cause of CVE-2025-7024.
*   Enable Sysmon file creation event logging (Event ID 11) to improve visibility into file creation activity on the Windows Server system, which is necessary for the Sigma rules.
