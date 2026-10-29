---
brief_id: brief-2026-10-29-foxit-info-exposure
event_id: brief-2026-10-29-foxit-info-exposure
revision: 1
activity_at: "2026-10-29T11:14:15Z"
title: 'Foxit: Sensitive information exposure via exposed credentials in JavaScript (CVE-2026-111419)'
slug: 2026-10-foxit-info-exposure
description: The Foxit official website exposes third-party authorization credentials within its client-side JavaScript code, allowing unauthorized parties to potentially harvest and misuse sensitive information.
date: "2026-10-29T11:14:15Z"
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
  validation_status: No Sigma rule possible as no specific log-observable execution path exists.
cpes:
  - cpe:2.3:a:foxit:foxit.com:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - information-exposure
  - credential-access
vendors:
  - Foxit
products:
  - foxit.com
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: A sensitive information exposure vulnerability exists on the Foxit official website because JavaScript code contains third-party authorization information.
    confidence_band: high
cves:
  - id: CVE-2026-111419
    cvss: 8.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111419
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Web Security Team
  immediate_actions:
    - action: Rotate all third-party authorization secrets identified within the Foxit web property
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows unauthorized parties to obtain or misuse exposed credentials
  hunt_leads:
    - lead: Inspect web asset repositories or proxy logs for historical access to client-side JS files containing high-entropy strings or known credential patterns
      technique_id: T1552.001
      data_needed:
        - Proxy logs
        - Web asset source code
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Credentials embedded within JavaScript code
  mitigation_plan:
    - priority: immediate
      action: Remove hardcoded secrets from client-side JS and move to a server-side authenticated proxy approach
      owner: Web Security Team
      addresses: CVE-2026-111419
      evidence: JavaScript code contains third-party authorization information
---

Foxit's official website has been identified as containing hardcoded third-party authorization credentials within its client-side JavaScript files. By inspecting the publicly accessible scripts, unauthorized actors can extract these credentials, leading to potential unauthorized access or misuse of third-party services integrated with the Foxit domain.

## Impact
Unauthorized actors can obtain sensitive authorization tokens or secrets, which may allow for unauthorized access to third-party services linked to the Foxit infrastructure.

## Recommendation
- Review all client-side JavaScript files on corporate-controlled websites for embedded secrets or credentials.
- Implement a secret scanning solution for web repositories to prevent the accidental exposure of sensitive keys.
- Rotate all third-party credentials identified within the affected JavaScript files on the Foxit website immediately.
