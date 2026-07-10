---
title: Windows AD Domain Replication ACL Addition Detection
slug: 2024-01-ad-domain-replication-acl-addition
description: This brief details the detection of unauthorized modifications to Active Directory domain replication Access Control Lists (ACLs), specifically targeting permissions that enable DCSync attacks, potentially leading to sensitive data exfiltration and privilege escalation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - active-directory
  - dcsync
  - acl
  - windows
  - privilege-escalation
  - persistence
vendors:
  - Microsoft
products:
  - Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1484
    technique_name: Domain Policy Modification
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain Policy Modification
references:
  - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
  - https://github.com/SigmaHQ/sigma/blob/29a5c62784faf986dc03952ae3e90e3df3294284/rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml
  - https://lantern.splunk.com/Security/Product_Tips/Enterprise_Security/Enabling_an_audit_trail_from_Active_Directory
rules:
  - title: Detect Addition of DCSync Permissions via dsacls.exe
    description: Detects the use of dsacls.exe to add permissions required for DCSync attacks (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All) to an Active Directory object.
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
  - title: Detect AD Object ACL Modification with Replication Rights via PowerShell
    description: Detects PowerShell being used to modify Active Directory object ACLs, specifically adding replication rights associated with DCSync.
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
rules_count: 2
---

This threat brief focuses on detecting malicious actors attempting to add specific permissions to Active Directory (AD) domain replication ACLs. The targeted permissions include DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, and DS-Replication-Get-Changes-In-Filtered-Set. Attackers often add these permissions to accounts, enabling them to perform DCSync attacks. This allows them to mimic a domain controller and replicate sensitive information, including password hashes, from the AD database. This activity is often a precursor to broader attacks such as privilege escalation, lateral movement, and data exfiltration. Defenders need to monitor for unauthorized modifications to AD replication permissions to prevent attackers from gaining a foothold and compromising the entire domain. The detection relies on Windows Event Code 5136, which logs changes to directory service objects. The Splunk search provided is adapted from splunk-escu and available on Github.

## Attack Chain

1. **Initial Compromise:** An attacker gains initial access to a system within the target network, potentially through phishing or exploiting vulnerabilities.
2. **Privilege Escalation:** The attacker escalates privileges to a domain-joined account with sufficient rights to modify ACLs.
3. **Permission Modification:** The attacker utilizes tools like PowerShell or native Windows utilities (e.g., `dsacls.exe`) to modify the ACL of the domain object. They grant the target account the necessary permissions (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, DS-Replication-Get-Changes-In-Filtered-Set).
4. **DCSync Execution:** The attacker leverages a tool like Mimikatz to perform a DCSync attack, impersonating a domain controller.
5. **Data Replication:** The attacker initiates replication, pulling sensitive data such as password hashes and Kerberos keys from the Active Directory database (NTDS.DIT).
6. **Credential Harvesting:** The attacker cracks the harvested password hashes to obtain plaintext credentials.
7. **Lateral Movement:** Using the compromised credentials, the attacker moves laterally within the network, gaining access to additional systems and resources.
8. **Data Exfiltration/Ransomware Deployment:** The attacker exfiltrates sensitive data or deploys ransomware across the compromised network, achieving their ultimate objective.

## Impact

Successful modification of AD replication ACLs and subsequent DCSync attacks can have devastating consequences. An attacker can compromise the entire Active Directory domain, impacting all connected systems and user accounts. This can lead to widespread data breaches, financial losses, and reputational damage. The potential impact includes the theft of sensitive data, disruption of business operations, and the complete compromise of the organization's IT infrastructure. The detection identifies the preparatory stage of the attack before the sensitive information is replicated.

## Recommendation

*   Enable the Advanced Security Audit policy setting `Audit Directory Services Changes` within `DS Access` and configure a SACL for `everybody` to `Write All Properties` applied to the domain root and all descendant objects to generate Windows Event Code 5136 (as mentioned in the "how_to_implement" section).
*   Deploy the provided Sigma rules to your SIEM to detect unauthorized modifications to AD replication ACLs. Tune the rules based on your environment to minimize false positives.
*   Review and whitelist legitimate accounts that may require these permissions for valid administrative purposes (as mentioned in "known_false_positives"). Revoke unnecessary permissions.
*   Monitor for Event ID 5136 in the Windows Security Event Log, focusing on changes to the ACLs of domain objects.
*   Implement multi-factor authentication (MFA) for all privileged accounts to mitigate the impact of compromised credentials obtained through DCSync.
