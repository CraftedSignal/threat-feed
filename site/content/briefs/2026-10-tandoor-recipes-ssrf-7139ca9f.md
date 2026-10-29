---
brief_id: brief-2026-10-29-tandoor-recipes-ssrf-7139ca9f
event_id: brief-2026-10-29-tandoor-recipes-ssrf-7139ca9f
revision: 1
activity_at: "2026-10-29T20:00:39Z"
title: 'Tandoor Recipes: Server-side request forgery (CVE-2026-115810)'
slug: 2026-10-tandoor-recipes-ssrf-7139ca9f
description: Tandoor Recipes versions before 2.7.0 are vulnerable to SSRF in the Pestle importer, allowing authenticated low-privileged users to force server-side GET requests to arbitrary internal or external targets.
date: "2026-10-29T20:00:39Z"
lastmod: "2026-10-29T20:00:54Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Patch verification confirmed as best mitigation.
cpes:
  - cpe:2.3:a:tandoorrecipes:tandoor_recipes:*:*:*:*:*:*:*:*
  - cpe:2.3:a:tandoor_recipes:tandoor_recipes:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - ssrf
  - privilege-escalation
  - vulnerability
  - webserver
vendors:
  - Tandoor Recipes
products:
  - Tandoor Recipes (< 2.7.0)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: This allows attackers to perform internal reconnaissance, port scanning, and response exfiltration by forcing the server to issue requests to arbitrary network destinations.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can create their own space to obtain an admin group designation, then switch their active space to a victim space where they hold lesser privileges, causing the stale cached admin decision to authorize elevated access.
    confidence_band: high
cves:
  - id: CVE-2026-115810
    cvss: 7.7
    epss: 0.00245
    kev_status: "false"
  - id: CVE-2026-112342
    cvss: 7.1
    epss: 0.00268
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115810
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112342
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Tandoor Recipes to 2.7.0 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-115810 disclosure
  hunt_leads:
    - lead: Identify authenticated users importing Pestle JSON files containing unusual or internal-facing URL schemes in image fields.
      technique_id: T1595.005
      data_needed:
        - Application logs showing Pestle import events
        - Web server egress logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows users to force server-side GET requests via Pestle JSON import file.
    - lead: Identify rapid space switching followed by administrative access logs
      technique_id: T1068
      data_needed:
        - Application audit logs recording user ID, target space ID, and requested endpoint
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can create their own space to obtain an admin group designation, then switch their active space to a victim space where they hold lesser privileges
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Tandoor Recipes 2.7.0
      owner: IT Operations
      addresses: CVE-2026-115810
      evidence: Official patch release
    - priority: immediate
      action: Upgrade Tandoor Recipes to 2.7.0 or later
      owner: IT Operations
      addresses: CVE-2026-112342
      evidence: Tandoor Recipes before 2.7.0 contains an improper cache-key design
updates:
  - at: "2026-10-29T20:00:54Z"
    level: L2
    summary: added coverage for Tandoor Recipes (< 2.7.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112342
---

Tandoor Recipes before version 2.7.0 contains a server-side request forgery (SSRF) vulnerability within its Pestle importer component. An authenticated user with low privileges can supply a malicious image URL via a Pestle JSON import file. The application fails to route this input through its centralized, hardened SSRF filter, instead executing a raw `requests.get` call in `cookbook/integration/pestle.py`. This behavior allows the server to be used as a proxy to reach internal network resources, conduct service discovery, or exfiltrate sensitive data from internal services.

## Impact

Successful exploitation allows an authenticated attacker to perform port and service discovery on the internal network of the host server. Furthermore, the attacker can force the application to exfiltrate responses from internal-only endpoints back to the user through the stored recipe image.

## Recommendation

- Upgrade Tandoor Recipes to version 2.7.0 or later immediately to include the patch for CVE-2026-115810.
- Review web server access logs for anomalous outbound requests originating from the Tandoor application host.
- Segment the Tandoor Recipes host from sensitive internal network zones to mitigate the impact of potential SSRF exploitation.
