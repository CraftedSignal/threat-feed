---
brief_id: brief-2026-11-02-github-dependabot-disable
event_id: brief-2026-11-02-github-dependabot-disable
revision: 1
activity_at: "2026-11-02T15:08:50Z"
title: 'GitHub: Disabling Dependabot alerts and security updates'
slug: 2026-11-github-dependabot-disable
description: Adversaries may disable GitHub Dependabot alerts or security updates at the repository, organization, or enterprise level to conceal the introduction of malicious or vulnerable dependencies.
date: "2026-11-02T15:08:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source provides direct telemetry fields for detection
tags:
  - cloud
  - saas
  - github
  - defense-evasion
vendors:
  - GitHub
products:
  - GitHub (Repository, Organization, and Enterprise levels)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    subtechnique_id: T1562.001
    subtechnique_name: Disable or Modify Tools
    evidence: Adversaries may turn off Dependabot to reduce the chance that a malicious or vulnerable dependency they introduced is flagged; disabling it for an organization or enterprise removes this coverage across many repositories at once.
    confidence_band: high
references:
  - https://docs.github.com/en/code-security/getting-started/dependabot-quickstart-guide
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/defense_evasion_github_dependabot_disabled.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify unauthorized disablement of Dependabot alerts or security updates in GitHub audit logs.
      technique_id: T1562.001
      data_needed:
        - GitHub Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Adversaries may turn off Dependabot to reduce the chance that a malicious or vulnerable dependency they introduced is flagged.
  mitigation_plan:
    - priority: immediate
      action: Audit all repositories for Dependabot configuration status and re-enable if unexpectedly disabled.
      owner: IT Operations
      addresses: T1562.001
      evidence: Re-enable Dependabot alerts (and security updates if required by policy).
---

GitHub audit logs capture events where Dependabot alerts or automated security updates are disabled. This activity is a potential indicator of defense evasion, as it prevents GitHub from flagging malicious or vulnerable packages. Depending on the scope of the configuration change, an actor can remove automated security coverage from a single repository, an entire organization, or an enterprise environment. This often precedes the injection of malicious code or dependency tampering.

## Impact
Disabling Dependabot removes automated visibility into vulnerable and malicious packages, increasing the likelihood that supply-chain compromises go undetected by security tooling.

## Recommendation
- Monitor GitHub audit logs for the specific `disable` actions listed in the detection guidance below.
- Audit administrative access and programmatic tokens that have permissions to modify organization or enterprise security settings.
- Review repository commits and dependency manifest changes (e.g., package.json, go.mod, requirements.txt) occurring immediately before or after these disable events.
- Re-enable Dependabot features unless a documented and approved exception exists.
