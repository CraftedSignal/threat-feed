---
title: Stored XSS in Amundsen Frontend
slug: 2026-09-amundsen-xss
description: Amundsen frontend versions through 4.3.0 allow Stored Cross-Site Scripting via unsanitized rendering of metadata descriptions, enabling arbitrary JavaScript execution in victim browsers.
date: "2026-09-13T11:26:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:amundsen:frontend:*:*:*:*:*:*:*:*
tags:
  - web-security
  - xss
  - injection
vendors:
  - Amundsen
products:
  - Amundsen frontend (<= 4.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can inject malicious markup like img elements with onerror handlers into descriptions via the metadata service or Elasticsearch.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: executing JavaScript in every user's browser that views search results.
    confidence_band: high
cves:
  - id: CVE-2026-90772
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90772
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Amundsen frontend to a version post-4.3.0
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-90772 affects versions <= 4.3.0
  mitigation_plan:
    - priority: immediate
      action: Review Elasticsearch metadata for malicious img tags or script blocks
      owner: Application Security
      addresses: CVE-2026-90772
      evidence: Source document identifies injection vector via Elasticsearch
---

Amundsen frontend versions through 4.3.0 contain a Stored Cross-Site Scripting (XSS) vulnerability due to the improper use of React's dangerouslySetInnerHTML property. The application fails to sanitize table, dashboard, or feature descriptions rendered within ResourceListItem components. This allows an attacker who can influence the metadata ingested into Amundsen - typically via the metadata service or the underlying Elasticsearch index - to inject malicious HTML content. When a legitimate user views search results containing these compromised descriptions, the injected scripts (e.g., img elements with onerror handlers) execute within the context of the user's session. This could lead to credential theft, session hijacking, or unauthorized actions performed on behalf of the victim user within the Amundsen interface.

## Impact

Successful exploitation results in arbitrary JavaScript execution in the browser of any user who views search results containing malicious descriptions. This impacts all organizations using Amundsen frontend 4.3.0 or earlier, potentially exposing internal data lineage and business intelligence metadata to unauthorized manipulation or exfiltration.

## Recommendation

Prioritized actions for security teams:
- Update the Amundsen frontend to a version beyond 4.3.0 that implements HTML sanitization for description fields.
- Audit metadata sources (metadata service, Elasticsearch) to identify and remove existing malicious payload strings in table or dashboard descriptions.
- Implement a Content Security Policy (CSP) that restricts script execution to trusted domains to mitigate the impact of XSS, even if rendering logic remains flawed.
- Restrict write access to the metadata service and the Elasticsearch backend to authorized service accounts only to prevent unauthorized injection.
