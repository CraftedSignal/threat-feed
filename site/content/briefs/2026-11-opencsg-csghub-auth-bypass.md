---
brief_id: brief-2026-11-02-opencsg-csghub-auth-bypass
event_id: brief-2026-11-02-opencsg-csghub-auth-bypass
revision: 1
activity_at: "2026-11-02T15:48:27Z"
title: 'OpenCSG CSGHub: Authorization bypass via file resolve route (CVE-2026-120426)'
slug: 2026-11-opencsg-csghub-auth-bypass
description: OpenCSG CSGHub version 2.6.0-ce and earlier contains an authorization bypass vulnerability allowing remote, unauthenticated attackers to retrieve private repository files by injecting a malicious current_user parameter.
date: "2026-11-02T15:48:27Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source confirmed vulnerability; environment validation of parameter forwarding logic is required
cpes:
  - cpe:2.3:a:opencsg:csghub:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - web-application
  - repository-exposure
  - cve-2026-120426
vendors:
  - OpenCSG
products:
  - CSGHub (<= 2.6.0-ce)
cves:
  - id: CVE-2026-120426
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120426
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify unauthenticated requests to CSGHub file resolution endpoints containing the current_user parameter
      data_needed:
        - Web server or application gateway access logs
        - Request parameters (query strings)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can inject a percent-encoded current_user parameter into the file path, which the portal forwards with its server API key, to read files in private model, code or space repositories.
  mitigation_plan:
    - priority: immediate
      action: Monitor or block public access to CSGHub endpoints that handle file resolution
      owner: IT Operations
      addresses: CVE-2026-120426
      evidence: OpenCSG CSGHub through v2.6.0-ce contains an authorization bypass vulnerability in the unauthenticated file resolve route.
---

OpenCSG CSGHub versions through 2.6.0-ce are affected by an authorization bypass vulnerability in the unauthenticated file resolve route. An unauthenticated remote attacker can exploit this by injecting a percent-encoded 'current_user' parameter into the file path. When processed, the application incorrectly forwards this parameter along with its internal server API key, causing the system to treat the request as authorized and allowing access to files within private models, code, or space repositories.

## Impact
Successful exploitation allows for the unauthorized retrieval of sensitive data contained within private repositories, including source code, model weights, and other intellectual property hosted on the CSGHub instance.

## Recommendation
- Upgrade CSGHub to a patched version beyond 2.6.0-ce when available.
- Until patched, inspect web server access logs for anomalous requests to file resolution endpoints containing the 'current_user' parameter.
- Restrict access to CSGHub instances to internal networks or via VPN to reduce exposure to the public internet.
