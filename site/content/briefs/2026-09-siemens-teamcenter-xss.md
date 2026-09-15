---
title: Reflected Cross-Site Scripting Vulnerability in Siemens Teamcenter
slug: 2026-09-siemens-teamcenter-xss
description: An unauthenticated remote attacker can exploit a reflected XSS vulnerability in the Teamcenter authentication redirect flow to execute arbitrary JavaScript in the context of an authenticated user session.
date: "2026-09-15T16:31:40Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:siemens:teamcenter:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - xss
  - siemens
vendors:
  - Siemens
products:
  - Teamcenter (V2412 < 2412.0013)
  - Teamcenter (V2506 < 2506.0010)
  - Teamcenter (V2512 < 2512.2607)
  - Teamcenter (V2606 < 2606.2607)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: An unauthenticated remote attacker to inject arbitrary JavaScript into the browser of an authenticated user who loads a crafted URL.
    confidence_band: high
cves:
  - id: CVE-2026-58113
    cvss: 6.1
    epss: 0.00218
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-07
  - https://cert-portal.siemens.com/productcert/html/ssa-157465.html
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58113
rules:
  - title: Detects CVE-2026-58113 Exploitation - XSS via /auth/ Endpoint
    description: Detects potential XSS attempts against the Teamcenter authentication redirect flow by identifying suspicious script tags or event handlers within the URI query parameters.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: 'Patch Siemens Teamcenter to the minimum fixed versions: 2412.0013, 2506.0010, 2512.2607, or 2606.2607'
      owner: IT Operations
      due: 72h
      evidence: Vendor remediation guidance in SSA-157465
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to block requests to /auth/ containing JavaScript characters
      owner: Network Security
      addresses: CVE-2026-58113
      evidence: Vulnerability analysis in the advisory
---

Siemens Teamcenter versions V2412, V2506, V2512, and V2606 are vulnerable to a reflected cross-site scripting (XSS) vulnerability (CVE-2026-58113) located in the authentication redirect flow. The vulnerability arises due to improper neutralization of user-supplied input when reflected into HTML attribute contexts within the /auth/ endpoint. An unauthenticated attacker can craft a malicious URL containing payload-injected parameters to target an authenticated user. When the victim loads this URL, the injected script executes within the victim's active session, potentially allowing the attacker to perform actions on the user's behalf or access sensitive data. Siemens has released patched versions for the affected product families and advises users to upgrade immediately to remediate the flaw.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript within the context of an authenticated user's session. This could lead to session hijacking, unauthorized data exfiltration, or the performance of unauthorized actions within the Teamcenter application. The vulnerability affects critical manufacturing and information technology sectors globally.

## Recommendation

Prioritize patching affected Teamcenter installations to the versions specified by the vendor:
- Update Teamcenter V2412 to V2412.0013 or later.
- Update Teamcenter V2506 to V2506.0010 or later.
- Update Teamcenter V2512 to V2512.2607 or later.
- Update Teamcenter V2606 to V2606.2607 or later.
- Apply defense-in-depth strategies to isolate Teamcenter instances from the public internet, as recommended by the vendor.
