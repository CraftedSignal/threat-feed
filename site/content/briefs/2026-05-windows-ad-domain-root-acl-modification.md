---
title: Windows AD Domain Root ACL Modification
slug: 2026-05-windows-ad-domain-root-acl-modification
description: Modification of Access Control Lists (ACLs) on the Active Directory domain root object can grant attackers persistent and escalated privileges.
date: "2026-05-28T17:59:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - active-directory
  - persistence
  - privilege-escalation
vendors:
  - Microsoft
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
  - title: Detect Windows AD Domain Root ACL Modification via Event 5136
    description: Detects ACL modification performed on the domain root object based on event ID 5136.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1222.001
      - T1484
    data_sources:
      - process_creation
      - windows
  - title: Detect Granting Full Control over Domain Root
    description: Detects granting 'Full control' over domain root ACL.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1222.001
      - T1484
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Modifying Access Control Lists (ACLs) on the domain root object within Active Directory represents a high-impact change, potentially enabling attackers to establish persistent access and escalate privileges. This activity is detected by monitoring Windows Event Log security event 5136, specifically focusing on alterations to the domainDNS object class. The ACL modification allows an attacker to control the entire domain. All changes at the domain root level should be reviewed according to Microsoft's guidance. Identifying the source device by examining the logonID within EventCode 4624 is important during triage.

## Attack Chain

1.  An attacker gains initial access to a privileged account or leverages an existing compromised account.
2.  The attacker uses tools like PowerShell or `dsacls.exe` to modify the ACL of the domain root object.
3.  Windows Security event 5136 is generated, logging the changes to the ACL. This event includes details about the ObjectClass, ObjectDN, OperationType, and AttributeValue.
4.  The attacker adds a new Access Control Entry (ACE) that grants them excessive permissions, such as "Full control", "Write All Properties," or "Write Owner" to a chosen user or group.
5.  The attacker's account or group now has elevated privileges over the entire Active Directory domain.
6.  The attacker can then use these privileges to create new accounts, modify existing accounts, or install malicious software on domain controllers.
7.  The attacker achieves persistence by maintaining control over critical domain resources.
8.  The attacker achieves privilege escalation by gaining control over previously inaccessible resources.

## Impact

Successful modification of domain root ACLs can lead to a complete compromise of the Active Directory environment. This allows attackers to control all domain resources, including user accounts, computers, and applications. This can allow for data exfiltration, ransomware deployment, and disruption of critical business services. The impact is severe, potentially affecting thousands of users and causing significant financial losses.

## Recommendation

*   Enable Active Directory auditing and ensure that event 5136 is being collected and forwarded to your SIEM or security monitoring platform.
*   Implement the Sigma rules provided below to detect suspicious ACL modifications on the domain root object.
*   Investigate any detected modifications to the domain root ACLs, focusing on the `src_user` and `user` fields in the detection results.
*   Review the references provided for guidance on enabling AD auditing and understanding ACE strings.
*   Use a tool like AD ACL Scanner to regularly audit and baseline domain root ACL permissions and compare against expected configurations.
