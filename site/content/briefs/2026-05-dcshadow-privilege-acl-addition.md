---
title: Windows AD DCShadow Privilege Escalation via ACL Modification
slug: 2026-05-dcshadow-privilege-acl-addition
description: This detection identifies an Active Directory access-control list (ACL) modification event, which applies the minimum required extended rights to perform the DCShadow attack by modifying permissions on the domainDNS object.
date: "2026-05-28T17:58:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dcshadow
  - active_directory
  - acl
  - privilege_escalation
  - persistence
vendors:
  - Microsoft
  - Splunk
products:
  - Active Directory
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1484
    technique_name: Domain Policy Modification
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1207
    technique_name: ' Rogue Domain Controller'
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1222
    technique_name: Permissions Modification
references:
  - https://www.labofapenetrationtester.com/2018/04/dcshadow.html
  - https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1
  - https://trustedsec.com/blog/a-hitchhackers-guide-to-dacl-based-detections-part-1-a
  - https://lantern.splunk.com/Security/Product_Tips/Enterprise_Security/Enabling_an_audit_trail_from_Active_Directory
rules:
  - title: Detect DCShadow Privilege ACL Addition
    description: Detects ACL modifications granting privileges required for DCShadow attack (Event ID 5136) by checking for the specific GUIDs associated with replication rights.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1207
      - T1222.001
      - T1484
    data_sources:
      - process_creation
      - windows
  - title: Detect DCShadow Privilege ACL Addition - Event Log Security 5136
    description: Detects ACL modifications granting privileges required for DCShadow attack (Event ID 5136) by checking for the specific GUIDs associated with replication rights.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1207
      - T1222.001
      - T1484
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The DCShadow attack is a technique where an attacker registers a rogue domain controller (DC) with a legitimate Active Directory domain, and then uses this rogue DC to inject malicious changes into the AD database.  This allows attackers to make persistent modifications to the Active Directory environment without being detected through traditional event logs that monitor changes on legitimate DCs. This brief focuses on detecting the initial ACL modifications necessary to prepare for a DCShadow attack. Specifically, it identifies modifications to the domainDNS object's ACL, granting the attacker the rights needed to replicate changes to the AD database.  This activity is often a precursor to more overt malicious activity within the Active Directory environment.

## Attack Chain

1.  An attacker gains initial access to a system within the target network, potentially through phishing or exploiting a vulnerability.
2.  The attacker elevates privileges to a level where they can make changes to Active Directory ACLs.
3.  Using tools like PowerShell or custom scripts, the attacker modifies the ACL of the domainDNS object in Active Directory (Event ID 5136).
4.  The attacker grants specific extended rights, including "Add/Remove Replica In Domain", "Manage Replication Topology", and "Replication Synchronization", to a chosen account or group. This can be achieved by targeting the GUIDs "9923a32a-3607-11d2-b9be-0000f87a36b2", "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2", and "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2".
5.  The attacker registers a rogue domain controller with the Active Directory domain.
6.  The attacker leverages the rogue DC to replicate malicious changes into the Active Directory database, such as modifying user attributes or group memberships.
7.  The attacker can then use these modifications to achieve their objectives, such as gaining unauthorized access to sensitive data or systems.

## Impact

Successful DCShadow attacks can grant attackers persistent and stealthy control over an Active Directory environment.  This can lead to widespread data breaches, account compromise, and disruption of critical business services. The attacker gains the ability to manipulate identities and permissions, bypassing normal security controls. While the source does not specify a number of victims, organizations relying on Active Directory for authentication and authorization are at risk.

## Recommendation

*   Enable and monitor Windows Event Log Security, specifically Event ID 5136, to detect modifications to Active Directory objects as described in the Lantern article linked in the references.
*   Deploy the Sigma rule `Detect DCShadow Privilege ACL Addition` to your SIEM and tune it for your environment based on expected legitimate ACL changes.
*   Investigate any alerts generated by the Sigma rule, focusing on the `src_user` and `user` fields to identify the source and target of the ACL modifications.
*   Review and audit Active Directory ACLs on critical objects like the domainDNS to ensure they are configured according to the principle of least privilege.
*   Implement multi-factor authentication (MFA) for privileged accounts to prevent attackers from easily gaining the necessary credentials to perform DCShadow attacks.
