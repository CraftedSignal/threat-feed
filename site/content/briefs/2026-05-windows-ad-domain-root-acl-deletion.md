---
title: Windows AD Domain Root ACL Deletion
slug: 2026-05-windows-ad-domain-root-acl-deletion
description: The analytic detects ACL deletion on the domain root object in Active Directory by monitoring Windows Event Log Security event ID 5136, identifying significant AD changes with potentially high impact.
date: "2026-05-28T18:04:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - active-directory
  - acl
  - privilege-escalation
  - persistence
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Active Directory
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
  - title: Detect AD Domain Root ACL Deletion
    description: Detects deletion of ACLs on the Active Directory domain root object, indicative of potential privilege escalation or persistence attempts.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1222.001
    data_sources:
      - process_creation
      - windows
  - title: Detect AD Domain Root ACL Deletion - PowerShell
    description: Detects deletion of ACLs on the Active Directory domain root object using PowerShell cmdlets.
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
rules_count: 2
---

This analytic focuses on detecting the deletion of Access Control Lists (ACLs) performed on the domain root object within Active Directory. Such modifications represent a significant change with potentially high impact, as they can lead to privilege escalation and unauthorized access. This detection leverages Windows Event Log Security event ID 5136 to identify these changes, specifically focusing on `domainDNS` objects. The goal is to identify instances where ACL rights have been removed from the domain root, which could indicate malicious activity aimed at compromising the integrity and security of the Active Directory environment. Regular monitoring and review of changes at this level are critical to maintaining a secure AD infrastructure.

## Attack Chain

1.  An attacker gains initial access to a privileged account or compromises an existing account with sufficient privileges to modify Active Directory objects.
2.  The attacker uses native Windows tools like `dsacls.exe` or PowerShell cmdlets to modify the ACL of the domain root object.
3.  The attacker removes specific ACEs (Access Control Entries) that grant permissions to critical groups or users, effectively restricting their access or modifying their permissions. This generates Event ID 5136 with Operation Type "%%14675" (Attribute Deletion) and potentially "%%14674" (Attribute Addition) to replace the deleted ACEs with modified versions.
4.  The event logs record the changes, including the ObjectClass as `domainDNS`, the ObjectDN representing the distinguished name of the domain root, and the SubjectLogonId identifying the user who made the changes.
5.  The `old_value` field in the event log contains the ACE string representing the deleted permission, including the aceType, aceFlags, aceAccessRights, aceObjectGuid, and aceSid.
6.  The attacker may repeat this process for multiple ACEs, targeting different groups or users to achieve their desired level of access control modification.
7.  The attacker leverages the modified ACLs to escalate privileges, gain unauthorized access to resources, or establish persistence within the Active Directory environment.
8.  The attacker maintains covert access to the domain, potentially compromising critical systems or exfiltrating sensitive data.

## Impact

Successful deletion of ACLs on the domain root object can have severe consequences, including unauthorized privilege escalation, data breaches, and complete domain compromise. Attackers can leverage these changes to gain control over critical resources, disrupt services, and establish persistent access to the environment. While the exact number of victims may vary, organizations across various sectors that rely on Active Directory for authentication and access control are vulnerable. If this attack succeeds, it can lead to significant financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Enable and monitor Windows Event Log Security event ID 5136 for changes to Active Directory objects, particularly the domain root (ObjectClass=domainDNS), to activate detections (data_source).
*   Implement the provided Sigma rule `Detect AD Domain Root ACL Deletion` to identify suspicious ACL deletions on the domain root object (rules).
*   Investigate any identified instances of ACL deletion, focusing on the `src_user` and `SubjectLogonId` to determine the source of the change and the potential impact (rules, search).
*   Ensure that the `wineventlog_security` macro is correctly configured with appropriate indexes and lookups for SID resolution to enrich event data (search, how_to_implement).
*   Review and validate any ACL changes on the domain root object to ensure they align with organizational security policies and business requirements (description).
