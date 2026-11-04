---
brief_id: brief-2026-11-04-github-ssh-ca-modification
event_id: brief-2026-11-04-github-ssh-ca-modification
revision: 1
activity_at: "2026-11-04T15:44:01Z"
title: 'GitHub: Unauthorized SSH Certificate Authority or Requirement Modification'
slug: 2026-11-github-ssh-ca-modification
description: Adversaries who compromise an organization or enterprise owner account may disable mandatory SSH certificate requirements or destroy certificate authorities to facilitate persistence and defense evasion by enabling the use of unmanaged SSH keys.
date: "2026-11-04T15:44:01Z"
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
  - saas
  - github
  - persistence
  - defense-evasion
  - access-control
vendors:
  - GitHub
products:
  - GitHub (Organization and Enterprise)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    subtechnique_id: T1562.001
    subtechnique_name: Disable or Modify Tools
    evidence: After an owner account is compromised, these changes are a defense-evasion step that re-opens key-based access the organization previously centralized and time-bounded.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: Destroying a CA or disabling the requirement weakens Git access control and can let an adversary authenticate with keys the organization does not manage.
    confidence_band: high
references:
  - https://docs.github.com/en/organizations/managing-git-access-to-your-organizations-repositories/about-ssh-certificate-authorities
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/defense_evasion_github_ssh_certificate_controls_modified.toml
action_plan:
  priority: elevated
  owners:
    - SOC
  immediate_actions:
    - action: Configure monitoring for GitHub audit events ssh_certificate_authority.create, ssh_certificate_authority.destroy, and ssh_certificate_requirement.disable
      owner: Detection Engineering
      due: 48h
      evidence: Source documentation explicitly lists these actions as indicators of potential defense evasion
  hunt_leads:
    - lead: Identify SSH CA destruction or requirement disabling by non-authorized accounts
      technique_id: T1562.001
      data_needed:
        - GitHub audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Destroying the CA or dropping the requirement makes ordinary unmanaged SSH keys acceptable again.
  mitigation_plan:
    - priority: immediate
      action: Enforce SSH certificate requirements org-wide and restrict administrative management of CA settings
      owner: IT Operations
      addresses: T1556
      evidence: Harden by requiring SSH certificates org-wide, restricting who can manage the SSH CA and certificate requirement
---

GitHub organizations and enterprises can utilize SSH certificate authorities (CAs) to issue short-lived SSH certificates, mandating their use in place of personal SSH keys for Git access. This configuration centralizes access control and enforces time-bounded authentication. Unauthorized modifications to these settings, specifically the creation or destruction of a CA or the disabling of certificate requirements, significantly weaken access controls. Following an account takeover, an adversary may perform these actions to authenticate using unmanaged SSH keys, bypassing the organization's intended security posture.

## Impact

Successful unauthorized modification of SSH certificate requirements allows an adversary to authenticate to organizational repositories using persistent, unmanaged SSH keys. This weakens Git access control, bypasses centralized and time-bounded authentication policies, and provides a mechanism for sustained persistence and defense evasion.

## Recommendation

* Audit GitHub audit logs for `ssh_certificate_authority.create`, `ssh_certificate_authority.destroy`, and `ssh_certificate_requirement.disable` events.
* Restrict administrative privileges for managing SSH CAs and certificate requirements to a minimal set of trusted, highly monitored owner accounts.
* Implement automated alerting for any modification to SSH CA configurations or disabling of SSH certificate requirements.
* If unauthorized modifications are detected, immediately re-enable certificate requirements, restore the intended CA configuration, revoke any SSH keys added during the window of vulnerability, and rotate credentials for compromised accounts.
