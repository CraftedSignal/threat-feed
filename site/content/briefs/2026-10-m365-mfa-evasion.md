---
brief_id: brief-2026-10-21-m365-mfa-evasion
event_id: brief-2026-10-21-m365-mfa-evasion
revision: 1
activity_at: "2026-10-21T13:58:48Z"
title: 'Microsoft 365 Exchange: MFA enrollment notification email deletion'
slug: 2026-10-m365-mfa-evasion
description: Attackers who compromise accounts and register unauthorized MFA devices often delete the resulting notification emails to evade detection, a technique monitored via Microsoft 365 Exchange audit logs.
date: "2026-10-21T13:58:48Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against source rule logic
tags:
  - m365
  - defense-evasion
  - persistence
  - bec
  - cloud-security
vendors:
  - Microsoft
products:
  - Exchange Online
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    subtechnique_id: T1070.008
    subtechnique_name: Clear Mailbox Data
    evidence: Adversaries who compromise accounts and register their own MFA device often delete the notification emails to cover their tracks and prevent the legitimate user from noticing the unauthorized change.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    subtechnique_id: T1098.005
    subtechnique_name: Device Registration
    evidence: Adversaries who compromise accounts and register their own MFA device often delete the notification emails to cover their tracks and prevent the legitimate user from noticing the unauthorized change.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/o365/defense_evasion_mfa_notification_email_deleted.toml
  - https://cloud.google.com/blog/topics/threat-intelligence/expansion-shinyhunters-saas-data-theft
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule for M365 MFA notification email deletion
      owner: Detection Engineering
      due: 48h
      evidence: Source rule provides specific EQL/query logic for monitoring Exchange audit logs.
  hunt_leads:
    - lead: Search Exchange audit logs for deletions of emails containing MFA keywords
      technique_id: T1070.008
      data_needed:
        - Microsoft 365 Audit Logs (o365.audit)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Rule description explicitly identifies this as a technique used in BEC.
  mitigation_plan:
    - priority: immediate
      action: Enforce Conditional Access policies for MFA registration
      owner: IT Operations
      addresses: Persistence via device registration (T1098.005)
      evidence: Best practice to limit MFA registration to trusted locations.
---

Attackers who successfully compromise an account often register an unauthorized MFA device as a means of maintaining persistence. To prevent the legitimate user from noticing the security change and receiving the corresponding MFA enrollment or registration notification, adversaries frequently delete or move these emails to the deleted items folder. This behavior is a common indicator of business email compromise (BEC) and account takeover operations.

## Attack Chain
1. Initial access to user account gained via compromised credentials.
2. Actor navigates to account security settings or MFA registration portal.
3. Actor registers a new, attacker-controlled MFA device (e.g., authenticator app or phone number).
4. Microsoft 365 generates a security notification or enrollment confirmation email.
5. Actor identifies the specific notification email in the user's inbox.
6. Actor performs a soft delete, hard delete, or moves the email to the Deleted Items folder to hide evidence of the MFA change.

## Impact
Successful exploitation allows an adversary to maintain persistent access to a compromised account even if the legitimate user changes their password, as the attacker-controlled MFA device remains active.

## Recommendation
- Deploy detection logic to monitor Microsoft 365 audit logs for the deletion of emails with subject lines containing MFA-related keywords.
- Investigate any user account flagged for MFA notification deletion by reviewing Azure AD sign-in logs and MFA registration history.
- Implement conditional access policies to restrict MFA registration activity to trusted locations or managed devices to limit the impact of compromised credentials.
- Review inbox rules for unauthorized automated forwarding or deletion configurations that may be used to suppress security alerts.
