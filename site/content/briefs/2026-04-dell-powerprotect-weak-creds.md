---
title: Dell PowerProtect Data Domain Weak Credentials Vulnerability (CVE-2026-23853)
slug: 2026-04-dell-powerprotect-weak-creds
description: Dell PowerProtect Data Domain with Data Domain Operating System (DD OS) versions 7.7.1.0 through 8.5, 8.3.1.0 through 8.3.1.20, and 7.13.1.0 through 7.13.1.50, contain a use of weak credentials vulnerability (CVE-2026-23853) that can lead to unauthorized access by a local attacker.
date: "2026-04-17T08:16:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-23853
  - dell
  - powerprotect
  - data domain
  - weak credentials
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Use Of Weak Credentials
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-23853
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23853
  - https://www.dell.com/support/kbdoc/en-us/000450699/dsa-2026-060-security-update-for-dell-powerprotect-data-domain-multiple-vulnerabilities
iocs:
  - type: url
    value: https://www.dell.com/support/kbdoc/en-us/000450699/dsa-2026-060-security-update-for-dell-powerprotect-data-domain-multiple-vulnerabilities
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect Login Attempts with Default Usernames on Dell PowerProtect
    description: Detects login attempts using common default usernames on Dell PowerProtect Data Domain systems, indicating potential exploitation of weak credentials.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1110.001
    data_sources:
      - auth
      - linux
  - title: Detect Access to Sensitive Files After Login on Dell PowerProtect
    description: Detects access to sensitive configuration files or data directories on Dell PowerProtect Data Domain systems following a login event, which may indicate unauthorized access after exploiting weak credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - linux
  - title: Detect Commands Indicative of Privilege Escalation on Dell PowerProtect
    description: Detects the execution of commands commonly used for privilege escalation or system modification on Dell PowerProtect systems. This could indicate an attacker leveraging compromised credentials.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Dell PowerProtect Data Domain is affected by a vulnerability (CVE-2026-23853) stemming from the use of weak credentials in Data Domain Operating System (DD OS). This issue impacts Feature Release versions 7.7.1.0 through 8.5, LTS2025 release version 8.3.1.0 through 8.3.1.20, and LTS2024 release versions 7.13.1.0 through 7.13.1.50. An unauthenticated, local attacker could exploit this vulnerability to gain unauthorized access to the system. Exploitation does not require network access, but rather relies on the presence of weak default or easily guessable credentials within the affected DD OS versions. This vulnerability poses a significant risk to the confidentiality, integrity, and availability of data stored on the affected systems.

## Attack Chain

1.  An attacker gains local access to a Dell PowerProtect Data Domain system running a vulnerable DD OS version (7.7.1.0-8.5, 8.3.1.0-8.3.1.20, or 7.13.1.0-7.13.1.50).
2.  The attacker attempts to authenticate using default or weak credentials.
3.  Upon successful authentication with weak credentials, the attacker gains unauthorized access to the DD OS.
4.  The attacker escalates privileges within the DD OS using commands available through the compromised account.
5.  The attacker gains access to sensitive data, including backup configurations, data encryption keys, or stored data backups.
6.  The attacker exfiltrates sensitive data from the Data Domain system to a remote location.
7.  The attacker modifies backup configurations to disrupt or prevent future backups.

## Impact

Successful exploitation of CVE-2026-23853 allows an attacker with local access to gain unauthorized access to Dell PowerProtect Data Domain systems. This can lead to the compromise of sensitive data stored within the backups, including customer data, financial records, and intellectual property. The impact ranges from data breaches and financial losses to reputational damage and disruption of business operations. The affected systems are primarily used in enterprise environments, so a successful attack may impact hundreds of organizations.

## Recommendation

*   Apply the security update provided by Dell as described in DSA-2026-060 to remediate the weak credentials vulnerability detailed in CVE-2026-23853. The advisory URL is available in the references section.
*   Review and enforce strong password policies for all accounts on Dell PowerProtect Data Domain systems.
*   Monitor authentication logs for the use of default credentials and failed login attempts on the affected systems.
*   Restrict local access to Dell PowerProtect Data Domain systems to authorized personnel only.
