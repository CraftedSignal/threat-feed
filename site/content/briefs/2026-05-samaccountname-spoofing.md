---
title: Potential Privileged Escalation via SamAccountName Spoofing (CVE-2021-42278)
slug: 2026-05-samaccountname-spoofing
description: This rule detects potential privilege escalation attempts by exploiting CVE-2021-42278, which involves spoofing the samAccountName attribute to impersonate a domain controller and elevate privileges from a standard domain user to a domain administrator by identifying suspicious computer account name rename events where a machine account name is renamed to a user-like account name.
date: "2026-05-12T19:09:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:microsoft:windows_server_2004:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_20h2:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - windows
  - active-directory
  - cve-2021-42278
vendors:
  - Microsoft
products:
  - Active Directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2021-42278
    cvss: 7.5
    epss: 0.94066
references:
  - https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e
  - https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/
  - https://github.com/cube0x0/noPac
  - https://twitter.com/exploitph/status/1469157138928914432
  - https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
rules:
  - title: Detect SamAccountName Spoofing (CVE-2021-42278)
    description: Detects CVE-2021-42278 exploitation — suspicious computer account name rename event indicating potential privilege escalation attempt by spoofing the samAccountName attribute.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect SamAccountName Spoofing - Renamed Event (CVE-2021-42278)
    description: Detects CVE-2021-42278 exploitation — detects when a computer account (ends with $) is renamed to a non-computer account.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The rule identifies attempts to exploit CVE-2021-42278, a security vulnerability that allows attackers to impersonate a domain controller via samAccountName attribute spoofing. This vulnerability can be used to elevate privileges from a standard domain user to a user with domain admin privileges. The attack involves renaming a computer account (identified by a '$' suffix) to a user-like account name (without the '$' suffix). Successful exploitation can lead to complete domain compromise. This rule focuses on detecting the initial account rename activity, a critical step in the exploit chain.

## Attack Chain

1.  Attacker compromises a standard domain user account through phishing or other means.
2.  Attacker uses the compromised user account to rename a computer account's samAccountName attribute, removing the trailing '$'.
3.  The attacker leverages CVE-2021-42278 to request Kerberos tickets for the renamed account, effectively impersonating the computer account.
4.  The attacker uses the impersonated computer account to request privileged Kerberos tickets.
5.  The attacker authenticates to domain services using the privileged Kerberos tickets.
6.  Attacker gains control over critical domain resources and services.
7.  Attacker elevates privileges to domain administrator.
8.  Attacker achieves complete domain compromise, enabling data exfiltration, ransomware deployment, or other malicious activities.

## Impact

Successful exploitation of CVE-2021-42278 can lead to a complete compromise of the Active Directory domain. An attacker can gain domain administrator privileges, allowing them to control all domain resources, access sensitive data, deploy ransomware, and disrupt business operations. The vulnerability affects all unpatched Windows Server versions running Active Directory Domain Services.

## Recommendation

*   Enable Audit User Account Management to generate the necessary Windows Security Event Logs for detection. Reference: [Setup instructions](https://ela.st/audit-user-account-management).
*   Apply Microsoft's hardening changes for CVE-2021-42278 to mitigate the vulnerability. Reference: [KB5008102](https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e).
*   Deploy the Sigma rule `Detect SamAccountName Spoofing (CVE-2021-42278)` to detect suspicious computer account renames.
*   Investigate any alerts generated by the Sigma rule, focusing on the user account that initiated the rename and the target account.
