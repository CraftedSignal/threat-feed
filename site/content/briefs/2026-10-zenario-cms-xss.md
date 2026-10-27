---
brief_id: brief-2026-10-27-zenario-cms-xss
event_id: brief-2026-10-27-zenario-cms-xss
revision: 1
activity_at: "2026-10-27T08:32:04Z"
title: 'Tribalsystems Zenario CMS: Stored Cross-Site Scripting (CVE-2023-44771)'
slug: 2026-10-zenario-cms-xss
description: An authenticated attacker can exploit a stored Cross-Site Scripting vulnerability in Tribalsystems Zenario CMS version 9.4.59197 by injecting malicious JavaScript via the Page Layout administration feature.
date: "2026-10-27T08:32:04Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of existing CMS versions
cpes:
  - cpe:2.3:a:tribalsystems:zenario:9.4.59197:*:*:*:*:*:*:*
vendors:
  - Tribalsystems
products:
  - Zenario CMS (9.4.59197)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Scripting a vulnerability in the sanitization of the entry in the Page Layout allows injecting JavaScript code that will be executed when the user accesses the web page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: Cross Site Scripting vulnerability in ZenarioCMS v.9.4.59197 allows a local attacker to execute arbitrary code via a crafted script to the Page Layout.
    confidence_band: high
cves:
  - id: CVE-2023-44771
    cvss: 5.4
    epss: 0.00573
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SROMANHU-CVE-2023-44771_ZENARIOCMS--STORED-XSS---PAGE-LAYOUT
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SROMANHU-CVE-2023-44771_ZENARIOCMS--STORED-XSS---PAGE-LAYOUT&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all Zenario CMS instances and verify versioning.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability specifically targets Zenario CMS 9.4.59197.
  hunt_leads:
    - lead: Review audit logs for administrative account activity modifying Page Layout components.
      technique_id: T1190
      data_needed:
        - Application access logs
        - Administrative change logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The exploit requires authenticated access to the Page Layout section in the Administration Menu.
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to detect or block script tags in administrative input fields if patching is delayed.
      owner: IT Operations
      addresses: CVE-2023-44771
      evidence: Stored XSS vulnerability in administrative console.
---

CVE-2023-44771 is a stored Cross-Site Scripting (XSS) vulnerability affecting Tribalsystems Zenario CMS version 9.4.59197. The vulnerability exists due to insufficient input sanitization within the Page Layout administration module. An attacker with low-level administrative privileges can inject arbitrary JavaScript, which executes when other users or administrators access the affected web pages.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript in the context of the victim's session. This may lead to session hijacking, unauthorized administrative actions, or defacement of the affected website.

## Recommendation

1. Inventory all instances of Tribalsystems Zenario CMS 9.4.59197.
2. Restrict access to the "Page Layout" administration feature to trusted administrative accounts only.
3. Monitor for unauthorized or suspicious modifications to Page Layout templates.
4. Coordinate with the vendor to obtain a patch for this version, as stored XSS in administrative interfaces represents a significant risk to application integrity.
