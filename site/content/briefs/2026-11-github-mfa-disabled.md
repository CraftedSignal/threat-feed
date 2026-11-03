---
brief_id: brief-2026-11-03-github-mfa-disabled
event_id: brief-2026-11-03-github-mfa-disabled
revision: 1
activity_at: "2026-11-03T15:31:00Z"
title: 'GitHub: Unauthorized Disabling of Mandatory Two-Factor Authentication'
slug: 2026-11-github-mfa-disabled
description: Adversaries who have achieved administrative account takeover are disabling mandatory two-factor authentication (2FA) requirements in GitHub to lower security barriers for persistence and unauthorized access.
date: "2026-11-03T15:31:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - cloud
  - saas
  - github
  - identity-security
  - defense-evasion
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: An adversary who has taken over an owner or enterprise-admin account may disable the requirement to preserve password-based access, reduce friction for adding attacker-controlled accounts, and lower the organization's account-takeover resistance.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
    subtechnique_id: T1556.006
    subtechnique_name: Multi-Factor Authentication
    evidence: This rule triggers on business.disable_two_factor_requirement and org.disable_two_factor_requirement, which turn off the enforced two-factor authentication (2FA) requirement for an entire GitHub enterprise or organization.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/defense_evasion_github_mfa_requirement_disabled.toml
  - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IAM
  immediate_actions:
    - action: Review GitHub audit logs for business.disable_two_factor_requirement or org.disable_two_factor_requirement events
      owner: SOC
      due: 1h
      evidence: Source explicitly identifies these audit log events as indicators of unauthorized identity control changes.
  hunt_leads:
    - lead: Identify unauthorized changes to 2FA requirements using GitHub audit logs
      technique_id: T1556.006
      data_needed:
        - GitHub audit logs (event.action, user.name, github.actor_ip)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The rule identifies specific event actions that signal the downgrading of organization-wide authentication security.
  mitigation_plan:
    - priority: immediate
      action: Re-enable mandatory 2FA for all GitHub organizations and enterprises
      owner: IAM
      addresses: Security policy bypass
      evidence: Re-enable the required 2FA setting for the affected organization or enterprise as soon as the change is confirmed unauthorized.
---

GitHub audit logs provide visibility into identity-control changes that impact organization and enterprise security. Specifically, the actions 'business.disable_two_factor_requirement' and 'org.disable_two_factor_requirement' indicate that the enforced 2FA requirement has been removed. This change downgrades all members within the affected scope to password-only authentication and allows the invitation of new accounts without 2FA, significantly increasing the risk of unauthorized access, persistence, and data exfiltration. This activity is often a precursor to further malicious operations following an initial account takeover of an owner or enterprise-admin account.

## Impact
Removing the mandatory 2FA requirement immediately degrades the security posture of an entire GitHub organization or enterprise. Attackers may leverage this control change to maintain password-based persistence, facilitate the addition of attacker-controlled accounts with reduced friction, and bypass identity verification for subsequent high-impact modifications such as token generation, SSH key additions, or repository modifications.

## Recommendation
- Immediately audit current GitHub organization and enterprise security settings to confirm that 'Require 2FA' is enabled for all members.
- Establish automated alerting for any occurrence of the 'business.disable_two_factor_requirement' or 'org.disable_two_factor_requirement' audit events.
- Conduct an immediate review of audit logs for any identity-related changes (e.g., new owner/member additions, PAT or OAuth app grants, SSH key updates) occurring immediately following a 2FA disablement event.
- Implement a break-glass policy for emergency access that requires documented change-management tickets for any temporary security control bypasses.
- Force a sign-out of all active sessions and require mandatory re-enrollment in 2FA for all organization members if a disablement event is identified as unauthorized.
