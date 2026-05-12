---
title: AdminSDHolder SDProp Exclusion Added
slug: 2026-05-adminsdholder-sdprop-exclusion
description: Modification of the dsHeuristics attribute to exclude groups from SDProp in Active Directory can allow attackers to maintain persistent access to privileged accounts.
date: "2026-05-12T18:40:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - active-directory
  - persistence
  - adminsdholder
  - sdprop
vendors:
  - Microsoft
products:
  - Active Directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://www.cert.ssi.gouv.fr/uploads/guide-ad.html#dsheuristics_bad
  - https://petri.com/active-directory-security-understanding-adminsdholder-object
rules:
  - title: AdminSDHolder SDProp Exclusion Added
    description: Detects modifications to the dsHeuristics attribute on Active Directory objects that control SDProp exclusion.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: AdminSDHolder SDProp Exclusion via Windows Event ID 5136
    description: Detects modifications to the dsHeuristics attribute using Windows Security Event ID 5136.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: AdminSDHolder SDProp Exclusion Bit Manipulation
    description: Detects modifications to dsHeuristics via 5136 event with value manipulation
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

The SDProp (Security Descriptor Propagator) process in Active Directory is crucial for maintaining the security of privileged accounts and groups. It compares permissions on protected objects with those defined on the AdminSDHolder object, resetting any discrepancies. Attackers can exploit the dsHeuristics attribute to exclude specific groups from this process, allowing them to manipulate the permissions of these groups without the changes being reverted by SDProp. This can lead to long-term persistence, even if the AdminSDHolder object is properly configured. The modification is identified via Windows Event ID 5136, specifically targeting changes to the dsHeuristics attribute. This attack matters because it allows attackers to maintain unauthorized access to sensitive resources within the Active Directory environment, potentially leading to further compromise and data breaches.

## Attack Chain

1.  The attacker gains initial access to a privileged account capable of modifying Active Directory attributes.
2.  The attacker identifies the AdminSDHolder object and the groups currently protected by SDProp.
3.  The attacker modifies the dsHeuristics attribute using tools like ADSI Edit or PowerShell to exclude specific privileged groups (e.g., Domain Admins) from SDProp. This involves manipulating the binary representation of the attribute value.
4.  The attacker makes unauthorized changes to the permissions, group memberships, or other security settings of the excluded groups.
5.  SDProp no longer resets the permissions of the excluded groups to match the AdminSDHolder object, effectively preserving the attacker's modifications.
6.  The attacker leverages their persistent access to the compromised privileged accounts and groups to perform lateral movement, escalate privileges, and access sensitive data.
7.  The attacker may create new accounts and add them to the excluded groups, granting them persistent access to the domain.
8.  The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or complete domain compromise, using the persistently compromised accounts and groups.

## Impact

Successful exploitation allows attackers to maintain persistent access to privileged accounts, even after security configurations are supposedly reset by SDProp. This persistence can lead to widespread damage, including complete domain compromise, data exfiltration, and ransomware deployment. The scope of the impact depends on the level of access granted to the compromised accounts. If Domain Admins are compromised, the entire Active Directory forest can be considered at risk.

## Recommendation

*   Enable "Audit Directory Service Changes" and monitor Windows Security Event Logs for Event ID 5136 with `AttributeLDAPDisplayName : "dSHeuristics"` to detect modifications to the dsHeuristics attribute.
*   Deploy the Sigma rule "AdminSDHolder SDProp Exclusion Added" to your SIEM to detect suspicious modifications to the dsHeuristics attribute. Tune the rule based on your environment and known directory configuration workflows.
*   Investigate any detected modifications to the dsHeuristics attribute, focusing on the `winlog.event_data.OperationType` and `winlog.event_data.AttributeValue` fields to determine the nature of the change and the groups affected.
*   Correlate Event ID 5136 with Event ID 4624 (An account was successfully logged on) using `winlog.event_data.SubjectLogonId` to identify the source of the directory change.
*   Regularly review and validate the configuration of the AdminSDHolder object and the dsHeuristics attribute to ensure that privileged groups are properly protected by SDProp.
