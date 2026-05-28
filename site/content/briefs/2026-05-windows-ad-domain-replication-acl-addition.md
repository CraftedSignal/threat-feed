---
title: Windows AD Domain Replication ACL Addition
slug: 2026-05-windows-ad-domain-replication-acl-addition
description: This analytic detects the addition of permissions required for a DCSync attack, specifically DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, and DS-Replication-Get-Changes-In-Filtered-Set, leveraging Windows Security Event Log 5136 to identify when these permissions are granted, which indicates potential preparation for replicating AD objects and exfiltrating sensitive data.
date: "2026-05-28T17:58:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1484
  - windows
  - active-directory
vendors:
  - Microsoft
  - Splunk
products:
  - Active Directory
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1484
    technique_name: Domain Trust Modification
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain Trust Modification
references:
  - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
  - https://github.com/SigmaHQ/sigma/blob/29a5c62784faf986dc03952ae3e90e3df3294284/rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml
  - https://lantern.splunk.com/Security/Product_Tips/Enterprise_Security/Enabling_an_audit_trail_from_Active_Directory
rules:
  - title: Detect Windows AD Replication ACL Addition
    description: Detects the addition of Active Directory replication permissions to an account, which is a common step in DCSync attacks.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1484
    data_sources:
      - process_creation
      - windows
  - title: Detect Event ID 5136 Adding AD Replication Permissions
    description: Detects Event ID 5136 related to the addition of Active Directory replication permissions to an account, which indicates potential DCSync preparation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1484
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This detection identifies the addition of specific permissions related to AD domain replication, which are often abused in DCSync attacks. A DCSync attack allows an attacker to retrieve password hashes from the Active Directory database, granting them complete control over the domain. The detection focuses on Event ID 5136, which logs changes to Active Directory objects, specifically when the permissions "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", and "DS-Replication-Get-Changes-In-Filtered-Set" are added to a principal. This activity is a strong indicator of an attacker preparing to perform a DCSync attack. Successful exploitation can lead to widespread privilege escalation and data breaches within the organization's Active Directory environment.

## Attack Chain

1.  The attacker gains initial access to a system within the target network, possibly through compromised credentials or exploiting a vulnerability.
2.  The attacker escalates privileges to a level sufficient to modify Active Directory object permissions. This may involve exploiting local vulnerabilities or leveraging existing administrative privileges.
3.  The attacker uses tools like `dsacls.exe` or PowerShell cmdlets (e.g., `Add-ADPermission`) to modify the ACL of the domain object in Active Directory. They grant specific permissions (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, DS-Replication-Get-Changes-In-Filtered-Set) to an account they control.
4.  Windows Security Event 5136 is generated, logging the modification of the ACL.
5.  The attacker uses a tool like Mimikatz (specifically the `lsadump::dcsync` module) or custom scripts to initiate a DCSync attack, impersonating a domain controller.
6.  The attacker replicates sensitive information, including password hashes, from the Active Directory database (NTDS.DIT).
7.  The attacker cracks the password hashes to obtain plaintext passwords or uses them in pass-the-hash attacks to gain access to other systems within the domain.
8.  The attacker achieves complete control over the Active Directory domain, enabling them to compromise critical systems and data.

## Impact

A successful DCSync attack allows the attacker to gain complete control over the Active Directory domain. This enables them to compromise critical systems, steal sensitive data, and disrupt business operations. The impact could range from data breaches and financial losses to reputational damage and legal repercussions. Given that Active Directory is the backbone of many organizations' IT infrastructure, the compromise of AD can lead to widespread and severe damage across the entire enterprise.

## Recommendation

*   Enable the Advanced Security Audit policy setting `Audit Directory Services Changes` within `DS Access` and configure a SACL for `everyone` to `Write All Properties` applied to the domain root and all descendant objects to generate the necessary EventCode 5136 logs.
*   Deploy the Sigma rule "Detect Windows AD Replication ACL Addition" to your SIEM and tune the `windows_ad_domain_replication_acl_addition_filter` macro for known legitimate accounts (if any) with replication permissions.
*   Investigate any instances of EventCode 5136 where the permissions "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", or "DS-Replication-Get-Changes-In-Filtered-Set" are granted to new accounts.
*   Enumerate the domain policy to verify if existing accounts with access need to be whitelisted, or revoked as documented in the "how_to_implement" section of the original Splunk detection.
*   Ensure your identities lookup is configured with the sAMAccountName and objectSid of all AD user and computer objects as documented in the "how_to_implement" section of the original Splunk detection.
