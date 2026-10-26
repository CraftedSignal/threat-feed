---
brief_id: brief-2026-10-26-danmu-api-auth-bypass
event_id: brief-2026-10-26-danmu-api-auth-bypass
revision: 1
activity_at: "2026-10-26T17:03:25Z"
title: 'danmu_api: Authentication bypass via default configuration (CVE-2026-116485)'
slug: 2026-10-danmu-api-auth-bypass
description: An authentication bypass vulnerability in danmu_api before 1.21.7 allows unauthenticated attackers to modify server environment configurations and facilitate SSRF through crafted POST requests to environment management endpoints.
date: "2026-10-26T17:03:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Test defined in Sigma rules
tags:
  - web-vulnerability
  - authentication-bypass
  - ssrf
products:
  - danmu_api (< 1.21.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: danmu_api before 1.21.7 contains an authentication bypass vulnerability that allows unauthenticated attackers to modify server environment configuration
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Attacker can... trigger redeployment.
    confidence_band: high
cves:
  - id: CVE-2026-116485
    cvss: 9.8
    kev_status: "false"
references:
  - https://www.vulncheck.com/advisories/danmu-api-before-1.21.7-authentication-bypass-via-default-token-in-env-endpoints
  - https://github.com/huangxd-/danmu_api/commit/6e93478064a0ce4e7ed3bc2eae88adaad1b7ab02
  - https://sploitus.com/exploit?id=CVE-2026-116485&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-116485 Exploitation - Unauthenticated Environment Modification
    description: Detects exploitation attempts against danmu_api environment configuration endpoints
    platform: sigma
    severity: critical
    tactics:
      - impact
      - initial_access
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch danmu_api to version 1.21.7 or later
      owner: IT Operations
      due: 24h
      evidence: VulnCheck advisory recommends version 1.21.7
  hunt_leads:
    - lead: Search web logs for POST requests to /api/env/ paths originating from unexpected source IPs
      technique_id: T1190
      data_needed:
        - Web access logs (Method, URL)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly documents /api/env/set, /api/env/add, /api/env/del as exploitation vectors
  mitigation_plan:
    - priority: immediate
      action: Set a unique ADMIN_TOKEN environment variable
      owner: IT Operations
      addresses: CVE-2026-116485
      evidence: Source states vulnerability exists when ADMIN_TOKEN is unset
---

danmu_api versions prior to 1.21.7 are vulnerable to an unauthenticated authentication bypass when the 'ADMIN_TOKEN' environment variable is not explicitly configured, causing the application to fall back to a default token. Attackers can leverage this to send malicious requests to environment modification endpoints, leading to full configuration takeover.

## Attack Chain
1. Discovery: Attacker identifies a target running a vulnerable version of danmu_api with default configuration.
2. Access: Attacker interacts with the API using the known default token.
3. Exploitation: Attacker sends POST requests to '/api/env/set', '/api/env/add', or '/api/env/del'.
4. Configuration Modification: Attacker updates 'ADMIN_TOKEN' to take control, or modifies 'OTHER_SERVER' or 'PROXY_URL'.
5. Impact: Attacker executes arbitrary configuration changes, including redeployment or redirecting traffic for Server-Side Request Forgery (SSRF).

## Impact
Successful exploitation allows unauthenticated attackers to gain administrative control over the danmu_api instance. This can lead to persistent lockout of legitimate operators, arbitrary server environment modification, and server-side request forgery (SSRF) by manipulating proxy and server URLs.

## Recommendation
- Update danmu_api to version 1.21.7 or later immediately.
- If upgrading is not immediately possible, explicitly set the 'ADMIN_TOKEN' environment variable to a strong, unique value to override the vulnerable default.
- Review server environment configuration for unauthorized modifications using the hunt leads provided below.
