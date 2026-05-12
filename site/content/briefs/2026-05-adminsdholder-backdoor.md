---
title: AdminSDHolder Backdoor via Active Directory Modification
slug: 2026-05-adminsdholder-backdoor
description: Detects modifications to the AdminSDHolder object in Active Directory, which attackers can abuse via the SDProp process to implement a persistent backdoor by manipulating permissions on protected accounts and groups to regain administrative privileges.
date: "2026-05-12T18:38:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - active directory
  - adminsdholder
vendors:
  - Microsoft
products:
  - Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Persistence
references:
  - https://adsecurity.org/?p=1906
  - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_ad_adminsdholder.toml
rules:
  - title: Detect AdminSDHolder Modifications
    description: Detects changes to the AdminSDHolder object in Active Directory via Windows Security Event ID 5136.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Detect AdminSDHolder nTSecurityDescriptor Modifications
    description: Detects changes to the nTSecurityDescriptor attribute of the AdminSDHolder object in Active Directory via Windows Security Event ID 5136.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

The AdminSDHolder object in Active Directory defines the default security permissions for highly privileged accounts and groups. The Security Descriptor Propagator (SDProp) process periodically compares the permissions of these protected objects with those defined on the AdminSDHolder object. If discrepancies are found, SDProp resets the permissions on the protected accounts and groups to match those of the AdminSDHolder, ensuring consistent security. Attackers can exploit this mechanism to establish a persistent backdoor by modifying the AdminSDHolder object with malicious permissions. Any changes to AdminSDHolder will be propagated to all protected accounts and groups, granting the attacker persistent administrative control over the domain. This technique allows attackers to regain administrative privileges even after password resets or other security measures.

## Attack Chain

1.  Attacker gains initial access to a privileged account with sufficient permissions to modify the AdminSDHolder object (e.g., Domain Admins).
2.  The attacker uses tools like ADSI Edit, PowerShell, or other Active Directory management tools to modify the AdminSDHolder object.
3.  The attacker modifies the nTSecurityDescriptor attribute on the AdminSDHolder object to include malicious ACEs (Access Control Entries) that grant unauthorized access to the attacker's account.
4.  SDProp automatically runs, typically every 60 minutes, comparing the permissions on protected accounts and groups with those defined on AdminSDHolder.
5.  SDProp identifies discrepancies between the permissions on protected objects and the modified AdminSDHolder object.
6.  SDProp resets the permissions on all protected accounts and groups to match those defined on the modified AdminSDHolder object.
7.  The attacker's account is now granted persistent, unauthorized administrative privileges on all protected accounts and groups in the domain.
8.  The attacker leverages the gained privileges to perform malicious activities such as data exfiltration, lateral movement, or establishing further persistence.

## Impact

Successful exploitation allows attackers to establish a persistent backdoor in the Active Directory environment. This grants them unauthorized administrative privileges over all protected accounts and groups, including Domain Admins, Enterprise Admins, and Schema Admins. The impact includes potential data breaches, complete domain compromise, and long-term persistence within the network. The attacker can maintain control even after password resets or other security measures are implemented.

## Recommendation

*   Enable "Audit Directory Service Changes" to generate Windows Security Event ID 5136, which is necessary for detecting modifications to the AdminSDHolder object as indicated in the rule overview.
*   Deploy the provided Sigma rule to your SIEM to detect unauthorized modifications to the AdminSDHolder object via event code 5136. Tune the rule based on your environment to minimize false positives.
*   Regularly review and baseline the nTSecurityDescriptor attribute of the AdminSDHolder object. Any unexpected changes should be investigated immediately.
*   Monitor for Event ID 5136 events that correlate with changes to protected accounts and groups immediately after an AdminSDHolder modification.
