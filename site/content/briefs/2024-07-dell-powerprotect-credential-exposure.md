---
title: Dell PowerProtect Data Domain BoostFS Credential Exposure Vulnerability (CVE-2025-36568)
slug: 2024-07-dell-powerprotect-credential-exposure
description: Dell PowerProtect Data Domain BoostFS versions 7.7.1.0 through 8.5, 8.3.1.0 through 8.3.1.20, and 7.13.1.0 through 7.13.1.50 are vulnerable to an insufficiently protected credentials vulnerability, allowing a low-privileged attacker with local access to expose credentials and potentially gain elevated privileges.
date: "2026-04-17T09:16:05Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - credential-exposure
  - dell
  - powerprotect
  - CVE-2025-36568
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2025-36568
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-36568
rules:
  - title: Detect Suspicious Access to Dell PowerProtect BoostFS Credential Files
    description: Detects suspicious processes accessing credential-related files in Dell PowerProtect Data Domain BoostFS.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Process Execution from Dell PowerProtect BoostFS Directory
    description: Detects suspicious process execution from the Dell PowerProtect Data Domain BoostFS installation directory, which might indicate exploitation or malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2025-36568 affects Dell PowerProtect Data Domain BoostFS for client software, specifically Feature Release versions 7.7.1.0 through 8.5, LTS2025 release versions 8.3.1.0 through 8.3.1.20, and LTS2024 release versions 7.13.1.0 through 7.13.1.50. The vulnerability stems from insufficiently protected credentials, potentially allowing a low-privileged attacker with local system access to expose sensitive information. Successful exploitation could allow the attacker to access the system with the privileges associated with the compromised account. This vulnerability poses a significant risk to organizations using the affected software, as it can lead to unauthorized access and potential data breaches. Defenders should prioritize patching or mitigating this vulnerability to prevent exploitation.

## Attack Chain

1.  Attacker gains low-privileged local access to a system running a vulnerable version of Dell PowerProtect Data Domain BoostFS.
2.  Attacker identifies the location of the insufficiently protected credential files within the BoostFS installation.
3.  Attacker leverages standard file system tools (e.g., `cat`, `type`, or a file explorer) to access and read the credential files.
4.  The attacker extracts the exposed credentials from the files. These credentials could include usernames, passwords, API keys, or other sensitive information.
5.  Attacker uses the compromised credentials to authenticate to the PowerProtect Data Domain system.
6.  Upon successful authentication, the attacker gains access to the system with the privileges of the compromised account.
7.  Attacker leverages their compromised account to escalate privileges further within the Data Domain system, potentially gaining administrative control.
8.  Attacker uses compromised access to exfiltrate sensitive data, disrupt backups, or deploy ransomware.

## Impact

Successful exploitation of CVE-2025-36568 allows a low-privileged local attacker to expose credentials stored by Dell PowerProtect Data Domain BoostFS. This can lead to unauthorized access to the Data Domain system, potentially granting the attacker the same privileges as the compromised account. Depending on the privileges of the compromised account, this could lead to a full system compromise, data exfiltration, backup disruption, and potential ransomware deployment. The impact is significant for organizations relying on PowerProtect Data Domain for data protection, as it can compromise the integrity and availability of their backups.

## Recommendation

*   Upgrade Dell PowerProtect Data Domain BoostFS to a patched version that addresses CVE-2025-36568. Refer to Dell's security advisory for specific upgrade instructions.
*   Monitor file access events for suspicious access to files within the Dell PowerProtect Data Domain BoostFS installation directory. Deploy the Sigma rule "Detect Suspicious Access to Dell PowerProtect BoostFS Credential Files" to your SIEM and tune for your environment.
*   Implement strong access controls to restrict local access to systems running Dell PowerProtect Data Domain BoostFS.
*   Regularly audit user accounts and privileges on the PowerProtect Data Domain system to identify and remove unnecessary accounts or excessive privileges.
*   Enable logging and alerting for successful and failed login attempts to the PowerProtect Data Domain system to detect potential unauthorized access attempts.
