---
title: Abuse of Active Directory DSRM Password Reset for Persistence
slug: 2026-10-dsrm-password-reset
description: Attackers may reset the Directory Services Restore Mode (DSRM) administrator password on Domain Controllers to maintain persistent, high-privileged administrative access.
date: "2026-10-12T18:00:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*
tags:
  - persistence
  - windows
  - active-directory
vendors:
  - Microsoft
products:
  - Active Directory Domain Services
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: The DSRM account can be used similarly to a local administrator account, providing potential persistence for an attacker.
    confidence_band: high
references:
  - https://adsecurity.org/?p=1714
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1098/T1098.yaml#L533
rules:
  - title: Detect DSRM Administrator Password Reset
    description: Detects the reset of the DSRM administrator password on a Domain Controller, which may indicate an attempt to establish persistent access.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Enable 'Audit User Account Management' GPO on all Domain Controllers.
      owner: IT Operations
      due: 48h
      evidence: Required for log generation as per documentation.
    - action: Deploy detection rule for Windows Event ID 4794.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides Event ID 4794 as the core detection mechanism.
  hunt_leads:
    - lead: Historical analysis of Event ID 4794 over the last 90 days.
      technique_id: T1098
      data_needed:
        - Windows Security Event Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Activity is highly anomalous and indicates potential persistence.
  mitigation_plan:
    - priority: medium_term
      action: Restrict access to Domain Controller administrative tools and limit the number of users with permissions to reset DSRM passwords.
      owner: IT Operations
      addresses: T1098
      evidence: Prevents unauthorized account manipulation.
---

The Directory Services Restore Mode (DSRM) account acts as a local administrator for the Active Directory database on a Domain Controller. Attackers who have already achieved high-level privileges in a Windows domain environment often target this account to establish a secondary persistence mechanism. By resetting the DSRM password, an adversary can bypass standard Active Directory authentication controls, allowing them to maintain access to the domain even if standard domain administrator credentials are rotated or revoked. This technique is specifically effective for long-term stealthy persistence within a compromised domain. Defenders should monitor for unexpected modifications to this account, as legitimate resets are infrequent and typically associated with disaster recovery operations or initial domain setup.

## Attack Chain

1. Attacker gains administrative access to the Domain Controller (often via compromised Domain Admin or Enterprise Admin credentials).
2. Attacker identifies the target Domain Controller to establish persistence.
3. Attacker executes an account management command (such as 'ntdsutil') to modify the DSRM administrator password.
4. The operating system triggers Windows Security Event ID 4794 to record the password change.
5. Attacker verifies the password change succeeds by observing administrative success logs or direct verification.
6. Attacker maintains a back-door mechanism using the DSRM credentials for future access to the domain database.

## Impact

Successful abuse of the DSRM account grants an attacker equivalent-to-local-administrator access to the Domain Controller. This allows for total control over the domain database, the ability to extract sensitive domain secrets, and the modification of Active Directory objects. This persistence mechanism is particularly dangerous as it persists beyond standard account credential changes, potentially leading to long-term undetected domain compromise.

## Recommendation

* Enable the 'Audit User Account Management' subcategory within the 'Account Management' audit policy to ensure Event ID 4794 is generated.
* Implement centralized logging for Windows Security Event ID 4794 across all Domain Controllers.
* Deploy detections to identify unauthorized usage or resets of the DSRM password, treating any such activity as a high-priority incident requiring immediate verification with IT operations.
