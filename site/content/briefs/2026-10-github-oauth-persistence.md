---
title: GitHub OAuth Application Authorization Persistence
slug: 2026-10-github-oauth-persistence
description: Attackers can achieve persistent unauthorized access to GitHub repositories by abusing OAuth application grants, which remain valid even after user password resets.
date: "2026-10-01T20:15:23Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud-security
  - saas-security
  - identity-threats
  - persistence
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Detects when a user authorizes a GitHub OAuth application. Stolen OAuth grants persist after password changes until revoked.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: Stolen OAuth grants persist after password changes until revoked and can clone or ZIP private repositories.
    confidence_band: high
references:
  - https://securitylabs.datadoghq.com/articles/mapping-out-your-unknown-threat-hunters-guide-to-github/
  - https://github.blog/news-insights/company-news/security-alert-stolen-oauth-user-tokens/
  - https://github.blog/news-insights/company-news/security-alert-new-phishing-campaign-targets-github-users/
  - https://docs.github.com/en/apps/oauth-apps/using-oauth-apps/authorizing-oauth-apps
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Implement audit log monitoring for oauth_authorization.create events.
      owner: Detection Engineering
      due: 72h
      evidence: Source rule definition.
  hunt_leads:
    - lead: Review recent oauth_authorization.create events for applications not on the approved allowlist.
      technique_id: T1078.004
      data_needed:
        - GitHub audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Investigation guide suggests auditing OAuth applications.
---

This threat involves the abuse of GitHub OAuth application authorization (`oauth_authorization.create`) to establish persistent access to an environment. Unlike GitHub App installations, user-authorized OAuth applications provide tokens that grant the application access to the user's data, including private repositories. A critical risk is that these OAuth grants persist even if the user changes their GitHub account password, as the authorization is tied to the grant rather than just the user's credentials. Attackers leverage this mechanism to maintain access to repositories, clone code, or download ZIP archives long after initial compromise. Detection of this activity requires monitoring GitHub audit logs for OAuth grant events and pivoting to subsequent repository access logs.

## Impact

Successful exploitation allows attackers to clone private repositories or download source code, potentially leading to the exfiltration of sensitive intellectual property, secrets, or API keys. Because these grants persist beyond password resets, this technique provides a durable backdoor into development environments, affecting organizations relying on GitHub for code hosting and CI/CD pipelines.

## Recommendation

Detection and response teams should implement monitoring for unauthorized OAuth application grants and maintain strict governance over third-party integrations.

- Implement monitoring for the `oauth_authorization.create` action within GitHub audit logs to alert on unexpected or suspicious application grants.
- Establish an allowlist of approved internal and vendor OAuth applications and investigate any grant that does not match this list.
- For suspected unauthorized access, immediately revoke the OAuth grant, invalidate existing tokens, reset the compromised user's password, and invalidate active sessions.
- Review organization-wide third-party application restrictions to limit the scope and risk of OAuth grants.
