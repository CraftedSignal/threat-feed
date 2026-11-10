---
brief_id: brief-2026-11-10-ssa-genesys
event_id: brief-2026-11-10-ssa-genesys
revision: 1
activity_at: "2026-11-10T19:00:28Z"
title: 'Social Security Administration genesys: Supply chain dependency on compromised polyfill.io domain (CVE-2026-104375)'
slug: 2026-11-ssa-genesys
description: The Social Security Administration genesys toolkit and the bundled Mavo v0.2.0 library contain hardcoded references to the hostile-owned cdn.polyfill.io domain, posing a supply-chain risk of malicious script injection into downstream applications.
date: "2026-11-10T19:00:28Z"
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
  - supply-chain
  - cve-2026-104375
  - javascript-injection
vendors:
  - Social Security Administration
products:
  - genesys (<= 2026-09-17)
  - Mavo (v0.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: The Genesys demo page... loads executable JavaScript from cdn.polyfill.io... which the README describes as ranging up to production-ready user interfaces.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Mavo dynamically injects a <script> for https://cdn.polyfill.io/v2/polyfill.min.js... This propagates the compromised reference into downstream prototypes.
    confidence_band: high
cves:
  - id: CVE-2026-104375
    kev_status: unknown
references:
  - https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/VA/white/2026/va-26-314-03.json
iocs:
  - type: domain
    value: cdn.polyfill.io
  - type: domain
    value: googie-anaiytics.com
ioc_counts:
  domain: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block cdn.polyfill.io and googie-anaiytics.com at the enterprise DNS resolver and proxy.
      owner: SOC
      due: 24h
      evidence: Domain is identified as hostile-controlled and serving malware.
  hunt_leads:
    - lead: Identify web servers or application frontends making outbound requests to cdn.polyfill.io.
      technique_id: T1189
      data_needed:
        - Proxy logs
        - DNS logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The toolkit automatically requests this domain when browser feature-detection triggers.
  mitigation_plan:
    - priority: immediate
      action: Update genesys toolkit applications to the post-2026-09-17 version.
      owner: IT Operations
      addresses: CVE-2026-104375
      evidence: Remediation is confirmed by the vendor as of 9/17/2026.
---

The Social Security Administration (SSA) genesys toolkit and the vendored Mavo v0.2.0 library contain hardcoded references to `cdn.polyfill.io`. This domain was sold to a hostile third party in February 2024 and has been observed serving malicious payloads, including redirects to phishing and scam sites. While the SSA demo page itself does not process user sessions or sensitive data, the toolkit is documented for use in production-ready user interfaces, creating a significant supply-chain risk for any application inheriting this dependency. The vulnerability is tracked as CVE-2026-104375. The repository was updated on 2026-09-17 to remove these references.

## Impact
Downstream applications utilizing the genesys toolkit or Mavo v0.2.0 are susceptible to arbitrary JavaScript injection via the hostile-controlled polyfill domain. Successful exploitation would allow attackers to execute malicious code within the context of the user's browser, enabling potential credential theft or redirection to fraudulent websites.

## Recommendation
- Audit all applications and prototypes derived from the genesys toolkit or Mavo v0.2.0 to identify and remove references to `cdn.polyfill.io`.
- Replace any dynamic script loading mechanisms that point to external, unverified CDNs with local hosting or trusted, static mirrors.
- Upgrade any projects using the genesys toolkit to the version released after 2026-09-17.
- Monitor web traffic logs for requests directed at `cdn.polyfill.io` or `googie-anaiytics.com` originating from web application frontends.
