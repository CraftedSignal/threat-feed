---
title: Unauthorized Modification of AdminSDHolder ACL in Active Directory
slug: 2026-10-adminsdholder-acl-modification
description: Attackers modify the Access Control List of the AdminSDHolder object in Active Directory to establish domain persistence and escalate privileges by leveraging the automated Security Descriptor Propagator process.
date: "2026-10-05T12:13:38Z"
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
  - Active Directory
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: The AdminSDHolder object secures privileged group members, and unauthorized changes can allow attackers to establish persistence and escalate privileges.
    confidence_band: high
rules:
  - title: Detect AdminSDHolder ACL Modification
    description: Detects modifications to the nTSecurityDescriptor attribute of the AdminSDHolder object, which may indicate unauthorized attempts to establish domain persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1546
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit SACL configuration on AdminSDHolder object
      owner: SOC
      due: 48h
      evidence: Source document requires SACL for event logging
  mitigation_plan:
    - priority: immediate
      action: Enable Audit Directory Services Changes policy
      owner: IT Operations
      addresses: Persistence via AdminSDHolder
      evidence: Standard defensive best practice for AD security
---

The AdminSDHolder object is a critical container in Active Directory that serves as a template for security permissions applied to high-privileged groups and accounts (e.g., Domain Admins, Enterprise Admins). The Security Descriptor Propagator (SDProp) process runs on the domain controller holding the PDC Emulator role and periodically propagates the ACL of the AdminSDHolder object to all protected objects in the domain. 

Attackers who gain sufficient privileges (typically Domain Admin or equivalent) can modify the AdminSDHolder ACL to grant themselves or a controlled security principal persistent access. Once the modification occurs, the SDProp process ensures that these permissions are consistently reapplied to protected objects, effectively bypassing manual remediation efforts and providing long-term persistence even if their original credentials are revoked. Monitoring this behavior is essential for detecting unauthorized domain-level privilege escalation attempts.

## Attack Chain

1. Attacker gains initial access and performs local reconnaissance to identify domain-level vulnerabilities.
2. Attacker escalates privileges to a level sufficient to modify Active Directory objects (e.g., Domain Admin).
3. Attacker identifies the AdminSDHolder object path in the domain (CN=AdminSDHolder,CN=System).
4. Attacker uses LDAP modification or Windows management tools to add a new Access Control Entry (ACE) to the AdminSDHolder's nTSecurityDescriptor attribute.
5. The Active Directory environment logs the modification via EventCode 5136.
6. The Security Descriptor Propagator (SDProp) runs (typically every 60 minutes).
7. SDProp applies the malicious ACL modification to all protected high-privileged groups and accounts.
8. Attacker leverages the newly granted permissions to maintain persistent administrative access across the Active Directory environment.

## Impact

Successful modification of the AdminSDHolder object allows an attacker to achieve domain-wide persistence and full administrative control over all high-privileged accounts. Because these permissions are managed by the automated SDProp process, simple modifications to group membership or account permissions by defenders are frequently overwritten, making this a highly durable persistence mechanism. This compromises the integrity and security of the entire domain, potentially leading to total loss of control over the identity infrastructure.

## Recommendation

1. Enable "Audit Directory Services Changes" within the "DS Access" advanced audit policy settings on all Domain Controllers.
2. Create a System Access Control List (SACL) for the AdminSDHolder object to ensure modifications are captured in security event logs.
3. Deploy the provided Sigma rule to detect EventCode 5136 occurrences where the AdminSDHolder ACL is modified.
4. Investigate all alerts triggered by this rule immediately, as unauthorized modifications to protected objects are rarely indicative of benign administrative activity.
