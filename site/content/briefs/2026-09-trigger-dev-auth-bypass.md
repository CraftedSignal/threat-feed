---
brief_id: brief-2026-09-16-trigger-dev-auth-bypass
event_id: brief-2026-09-16-trigger-dev-auth-bypass
revision: 1
activity_at: "2026-09-16T21:55:49Z"
title: Authentication Bypass in Trigger.dev via GitHub App Installation Binding
slug: 2026-09-trigger-dev-auth-bypass
description: Trigger.dev versions before 4.6.0 contain an authentication bypass vulnerability allowing attackers to hijack GitHub App installations and gain unauthorized repository access by manipulating state cookies and installation identifiers.
date: "2026-09-16T21:55:49Z"
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
  validation_status: Source documentation verified; no IOCs or specific log-observable TTPs provided to support Sigma rule generation.
cpes:
  - cpe:2.3:a:trigger:trigger.dev:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - github-integration
  - cloud-native
vendors:
  - Trigger.dev
products:
  - Trigger.dev (< 4.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Attackers can claim another user's GitHub App installation by replaying state cookies and supplying sequential installation identifiers, gaining unauthorized access to the victim's repositories.
    confidence_band: high
cves:
  - id: CVE-2026-92773
    cvss: 7.1
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92773
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DevOps
  immediate_actions:
    - action: Upgrade Trigger.dev to 4.6.0 or later.
      owner: IT Operations
      due: 24h
      evidence: Trigger.dev before 4.6.0 fails to verify that an authenticated user controls a GitHub App installation
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Trigger.dev 4.6.0 or later.
      owner: IT Operations
      addresses: CVE-2026-92773
      evidence: Trigger.dev before 4.6.0 fails to verify that an authenticated user controls a GitHub App installation
---

Trigger.dev versions prior to 4.6.0 contain a critical vulnerability related to how the platform validates the ownership of GitHub App installations during the binding process. The vulnerability stems from a failure to verify that an authenticated user actually controls or owns the GitHub App installation before associating it with their organization within the Trigger.dev platform.

An attacker can exploit this flaw by leveraging sequential installation identifiers combined with the replay of state cookies. By predicting or brute-forcing installation IDs and interacting with the authorization flow, an attacker can trick the system into binding a victim's GitHub App installation to the attacker's own organization. This results in the attacker gaining unauthorized access to the victim's GitHub repositories, effectively achieving account and resource takeover. This flaw represents a significant risk for organizations using Trigger.dev for workflow automation, as it allows for unauthorized access to sensitive source code and environment secrets.

## Impact

The vulnerability allows unauthorized access to GitHub repositories belonging to other users or organizations. If exploited, an attacker can gain the permissions granted to the hijacked GitHub App installation, potentially allowing for the theft of source code, environment secrets, or the manipulation of CI/CD pipelines connected to Trigger.dev.

## Recommendation

Prioritize the upgrade of Trigger.dev to version 4.6.0 or later to address the underlying authentication logic flaw in the GitHub App installation binding process.

* Upgrade Trigger.dev to version 4.6.0 or later immediately to patch CVE-2026-92773.
* Audit existing GitHub App installations within the Trigger.dev dashboard for any unknown or unauthorized organization associations.
* Review GitHub App permissions granted to the Trigger.dev integration to ensure minimal privilege is applied.
