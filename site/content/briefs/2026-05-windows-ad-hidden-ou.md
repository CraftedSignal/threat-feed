---
title: Windows AD Hidden Organizational Unit Creation
slug: 2026-05-windows-ad-hidden-ou
description: This analytic detects when an ACL is applied to an organizational unit (OU) to deny listing the objects residing in it; this activity, combined with modifying the owner of the OU, can hide Active Directory objects, even from domain administrators.
date: "2026-05-28T17:59:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - active-directory
  - persistence
  - privilege-escalation
  - windows
  - t1222.001
  - t1484
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1222
    technique_name: Permissions Abuse
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1484
    technique_name: Domain Policy Modification
references:
  - https://happycamper84.medium.com/sneaky-persistence-via-hidden-objects-in-ad-1c91fc37bf54
  - https://lantern.splunk.com/Security/Product_Tips/Enterprise_Security/Enabling_an_audit_trail_from_Active_Directory
rules:
  - title: Detect Windows AD Hidden OU Creation - Access Denied
    description: Detects the creation of a hidden OU by identifying access denied entries in the ACL.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1222.001
      - T1484
    data_sources:
      - windows
      - windows
  - title: Detect Windows AD Hidden OU Creation - List Contents Denied
    description: Detects the creation of a hidden OU by identifying list contents denied entries in the ACL.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1222.001
      - T1484
    data_sources:
      - windows
      - windows
rules_count: 2
---

This detection focuses on identifying attempts to hide Active Directory objects by manipulating organizational unit (OU) permissions. Attackers may modify the Access Control Lists (ACLs) of OUs to deny listing the objects residing within them. This technique, often coupled with changes to the OU's owner, effectively conceals AD objects from standard discovery methods, even for domain administrators. The detection leverages Windows Event Log Security event ID 5136 to monitor for these permission modifications on organizationalUnit objects. This is a post-exploitation technique used to maintain persistence or evade detection in a compromised Active Directory environment.

## Attack Chain

1. An attacker gains initial access to a system with sufficient privileges to modify Active Directory objects.
2. The attacker identifies a target Organizational Unit (OU) to hide.
3. The attacker modifies the ACL of the target OU using tools like PowerShell or built-in Windows utilities.
4. The modification involves adding an Access Control Entry (ACE) that denies "List contents" or "List objects" permissions to a specific user or group.
5. Windows Event Log Security generates event ID 5136 when the OU's ACL is modified.
6. The attacker may also change the owner of the OU to further obscure their activity.
7. The attacker leverages the hidden OU to store malicious objects (e.g., user accounts, group policy objects) for persistence or lateral movement.
8. The attacker maintains a foothold in the Active Directory environment, evading standard enumeration techniques.

## Impact

Successful execution of this technique allows attackers to maintain a persistent presence within the Active Directory environment, bypassing normal enumeration and auditing processes. This can lead to prolonged periods of undetected activity, enabling lateral movement, data exfiltration, or the deployment of ransomware. The hiding of OUs also complicates incident response efforts, potentially allowing the attackers to regain access after remediation attempts.

## Recommendation

*   Enable and monitor Windows Event Log Security, specifically event ID 5136, to capture Active Directory object modifications.
*   Deploy the Sigma rules provided to detect suspicious ACL modifications on Organizational Units (OUs).
*   Investigate any instances of event ID 5136 where the OperationType indicates modifications to permissions ("%%14674", "%%14675") and the ObjectClass is organizationalUnit.
*   Implement regular reviews of Active Directory object permissions, focusing on OUs with restricted visibility, to uncover hidden objects.
*   Consider implementing additional monitoring and alerting for changes to OU ownership.
