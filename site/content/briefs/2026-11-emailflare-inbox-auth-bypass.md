---
brief_id: brief-2026-11-04-emailflare-inbox-auth-bypass
event_id: brief-2026-11-04-emailflare-inbox-auth-bypass
revision: 1
activity_at: "2026-11-04T00:24:15Z"
title: 'emailflare: Missing authorization in inbox service (CVE-2026-121729)'
slug: 2026-11-emailflare-inbox-auth-bypass
description: An authorization bypass vulnerability in the emailflare inbox service allows authenticated users to manage global API keys, facilitating unauthorized mail relay and service disruption.
date: "2026-11-04T00:24:15Z"
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
cpes:
  - cpe:2.3:a:emailflare:emailflare:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - access-control
  - email-security
vendors:
  - emailflare
products:
  - emailflare (< commit cf31f33)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Attackers can mint a global live API key accepted by /v1/send to send mail from any domain, or revoke existing keys to disable integrations.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    subtechnique_name: Data Destruction
    evidence: revoke existing keys to disable integrations.
    confidence_band: high
cves:
  - id: CVE-2026-121729
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121729
rules:
  - title: Detect Potential CVE-2026-121729 Exploitation - Unauthorized API Key Management
    description: Detects unauthorized attempts to access or modify API keys in the emailflare inbox service by non-administrative users.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch emailflare to commit cf31f33 or later
      owner: IT Operations
      due: 48h
      evidence: emailflare before commit cf31f33 contains a missing authorization vulnerability
  hunt_leads:
    - lead: Identify abnormal API key lifecycle management by non-privileged accounts
      technique_id: T1552
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: allows any authenticated member to list, create and revoke API keys
  mitigation_plan:
    - priority: immediate
      action: Upgrade emailflare inbox service to commit cf31f33 or later
      owner: IT Operations
      addresses: CVE-2026-121729
      evidence: emailflare before commit cf31f33 contains a missing authorization vulnerability
---

The emailflare inbox service contains a missing authorization flaw in the /api/keys route. Any authenticated user can list, create, or revoke API keys, including global live API keys. This vulnerability allows an attacker to send emails from any domain managed by the platform or disable existing service integrations.

## Impact
Exploitation allows for unauthorized use of the mail-sending infrastructure (impersonation) and denial of service of legitimate user integrations via the revocation of active keys.

## Recommendation
- Upgrade emailflare to the version including commit cf31f33 or later immediately to patch the authorization logic.
- Audit existing API keys for unexpected creation or revocation events.
- Review access logs for non-admin accounts interacting with the /api/keys endpoint.
