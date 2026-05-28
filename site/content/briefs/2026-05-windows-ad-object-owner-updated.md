---
title: Windows AD Object Owner Updated
slug: 2026-05-windows-ad-object-owner-updated
description: This Splunk search detects when the owner of an Active Directory object is updated, potentially granting full control privileges and enabling object hiding, focusing on Windows Event Log ID 5136, and includes lookups for SID resolution.
date: "2026-05-28T17:59:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - active-directory
  - privilege-escalation
  - persistence
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Active Directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1222
    technique_name: Permissions Groups Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain Policy Modification
references:
  - https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
  - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
  - https://trustedsec.com/blog/a-hitchhackers-guide-to-dacl-based-detections-part-1-a
  - https://lantern.splunk.com/Security/Product_Tips/Enterprise_Security/Enabling_an_audit_trail_from_Active_Directory
rules:
  - title: Detect AD Object Owner Updated via Command Line
    description: Detects potential AD object owner modification via command-line tools like 'dsacls' or PowerShell cmdlets
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1222.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Windows Security Event 5136 - AD Object Owner Change
    description: Detects Windows Security Event ID 5136 indicating a change to an Active Directory object owner.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1222.001
    data_sources:
      - wineventlog
      - windows
rules_count: 2
---

This detection focuses on identifying modifications to Active Directory (AD) object ownership, an action that can grant extensive control over the affected object. Attackers may modify the owner of an AD object to escalate privileges, establish persistence, or conceal their presence within the AD environment. The Splunk search leverages Windows Event Log ID 5136 to detect these changes. This is a TTP-based detection that considers the significant impact of such changes and the potential for subsequent malicious activities. The detection logic involves monitoring changes to the owner attribute of AD objects and performing SID resolution to identify the new and previous owners, with a filter to focus only on changes.

## Attack Chain

1.  The attacker compromises an initial user account or system with sufficient privileges to modify AD objects.
2.  The attacker identifies a target AD object, such as a user, group, or computer account.
3.  The attacker uses AD management tools (e.g., PowerShell, ADSI Edit, or Mimikatz) to modify the "owner" attribute of the target object.
4.  The Windows Security Event Log generates an event with EventCode 5136, logging the attribute modification. OperationType values will indicate attribute additions or modifications.
5.  The attacker may change the object's owner to an account they control, or to a built-in group like "Domain Admins."
6.  The attacker uses the newly acquired ownership to manipulate the object's permissions (DACLs), potentially granting themselves full control.
7.  The attacker can now use the controlled object for persistence mechanisms or to further escalate privileges within the domain.
8.  The attacker may use their newly acquired control to hide the object.

## Impact

Successful modification of AD object ownership can lead to significant privilege escalation and persistence within the Active Directory environment. An attacker controlling the object's owner can manipulate permissions, compromise sensitive accounts, and establish long-term access. This activity can lead to data breaches, system compromise, and disruption of services. While the original source does not specify number of victims or targeted sectors, the broad applicability of Active Directory makes it relevant for virtually any Windows-based network.

## Recommendation

*   Enable and monitor Windows Security Event Log ID 5136 for Active Directory object modifications as referenced in the data source definition.
*   Deploy the Sigma rule `Detect AD Object Owner Updated via Command Line` to detect suspicious command-line activity related to AD object owner modifications.
*   Implement the Splunk search provided to detect changes in AD object ownership and tune the `windows_ad_object_owner_updated_filter` macro for your environment.
*   Investigate any detected instances of AD object owner modifications, focusing on the source user and the target object, as described in the finding title.
