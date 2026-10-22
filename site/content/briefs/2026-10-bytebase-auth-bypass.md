---
brief_id: brief-2026-10-22-bytebase-auth-bypass
event_id: brief-2026-10-22-bytebase-auth-bypass
revision: 1
activity_at: "2026-10-22T22:28:59Z"
title: 'Bytebase: Authentication bypass via GitLab provider configuration (CVE-2022-51026)'
slug: 2026-10-bytebase-auth-bypass
description: Bytebase versions prior to 1.0.1 are vulnerable to an authentication bypass in the GitLab login flow, allowing unauthenticated attackers to impersonate any user, including administrative accounts.
date: "2026-10-22T22:28:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - cpe:2.3:a:bytebase:bytebase:*:*:*:*:*:*:*:*
vendors:
  - Bytebase
products:
  - Bytebase (< 1.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: The flaw stems from trusting client-supplied GitLab provider configuration in the POST /api/auth/login/GITLAB_SELF_HOST endpoint.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Bytebase then issues session tokens for that principal, letting attackers impersonate existing users including the Owner or create new members.
    confidence_band: high
cves:
  - id: CVE-2022-51026
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-51026
rules:
  - title: Detect CVE-2022-51026 Exploitation - Authentication Bypass via GitLab Login
    description: Detects exploitation of CVE-2022-51026 - Attempts to POST to the GitLab self-hosted login endpoint, identifying potential malicious instanceUrl parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1133
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Bytebase to version 1.0.1 or later
      owner: IT Operations
      due: 48h
      evidence: Bytebase 0.12.0 before 1.0.1 contains an authentication bypass vulnerability
  hunt_leads:
    - lead: Identify successful POST requests to /api/auth/login/GITLAB_SELF_HOST with unrecognized instanceUrl
      technique_id: T1133
      data_needed:
        - Web access logs containing URI and query parameters
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can set instanceUrl to a server they control
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 1.0.1
      owner: IT Operations
      addresses: CVE-2022-51026
      evidence: Bytebase 0.12.0 before 1.0.1 contains an authentication bypass
---

Bytebase versions prior to 1.0.1 contain an authentication bypass vulnerability (CVE-2022-51026) in the `/api/auth/login/GITLAB_SELF_HOST` endpoint. The vulnerability exists because the application improperly trusts client-supplied GitLab provider configuration. An attacker can supply a malicious `instanceUrl` pointing to a server they control, which returns a fabricated active user response. Bytebase uses this response to generate session tokens, enabling the attacker to impersonate arbitrary users or create new accounts with elevated privileges.

## Impact
Successful exploitation allows unauthenticated attackers to gain unauthorized access to the Bytebase instance by impersonating existing users, including the Owner role, or by creating new members.

## Recommendation
- Upgrade Bytebase to version 1.0.1 or later immediately.
- Review access logs and audit trails for unexpected authentication events or suspicious user creations within Bytebase if the instance was exposed during the vulnerable period.
- Disable GitLab self-hosted authentication providers if they are not actively required for environment workflows.
