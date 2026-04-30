---
title: Windows Storage Spaces Controller Out-of-Bounds Read Privilege Escalation (CVE-2026-32076)
slug: 2026-04-windows-storage-spaces-privesc
description: CVE-2026-32076 is an out-of-bounds read vulnerability in the Windows Storage Spaces Controller that allows an authorized local attacker to elevate privileges.
date: "2026-04-15T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - cve-2026-32076
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32076
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32076
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32076
rules:
  - title: Suspicious Storage Spaces Controller Process Creation
    description: Detects suspicious process creations potentially related to exploitation of CVE-2026-32076
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Abnormal Access to Storage Spaces Controller Driver
    description: Detects abnormal access to the Storage Spaces Controller driver (spaceport.sys) from unusual processes
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - image_load
      - windows
rules_count: 2
---

CVE-2026-32076 is a critical vulnerability affecting the Windows Storage Spaces Controller. This out-of-bounds read vulnerability allows an attacker with local access and authorization to elevate their privileges on the system. The vulnerability was published on April 14, 2026. Successful exploitation could allow an attacker to gain higher-level access to the system, potentially leading to complete control. Due to the potential for privilege escalation, this vulnerability poses a significant risk to systems where Storage Spaces Controller is enabled. Defenders should prioritize patching and monitoring for any suspicious activity related to this component.

## Attack Chain

1. An attacker gains initial local access to a Windows system.
2. The attacker authenticates to the system with valid user credentials.
3. The attacker crafts a malicious input that triggers an out-of-bounds read within the Windows Storage Spaces Controller.
4. The crafted input leverages the vulnerability to read sensitive memory locations.
5. The attacker obtains privileged information from the memory, such as kernel addresses or security tokens.
6. The attacker uses the leaked privileged information to escalate their privileges to SYSTEM.
7. The attacker can now perform actions as a highly privileged user.
8. The attacker installs malicious software, modifies system settings, or exfiltrates sensitive data.

## Impact

Successful exploitation of CVE-2026-32076 allows a local attacker to elevate their privileges to SYSTEM, the highest level of privilege in Windows. This can lead to complete system compromise, including the installation of malware, data theft, and modification of system configurations. The vulnerability affects systems where Windows Storage Spaces Controller is enabled.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-32076 as soon as possible to prevent exploitation (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32076).
*   Monitor for suspicious process activity related to Storage Spaces Controller that could indicate exploitation attempts, and deploy the Sigma rules below.
*   Enable process auditing and monitor for unauthorized access attempts or modifications to Storage Spaces-related components to detect potential exploitation attempts.
