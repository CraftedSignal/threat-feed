---
brief_id: brief-2026-10-25-librenms-xss
event_id: brief-2026-10-25-librenms-xss
revision: 1
activity_at: "2026-10-25T16:45:29Z"
title: 'LibreNMS: Reflected Cross-Site Scripting (CVE-2025-66850)'
slug: 2026-10-librenms-xss
description: LibreNMS versions through 24.9.1 are vulnerable to a reflected cross-site scripting (XSS) attack via the routing module, enabling remote attackers to execute arbitrary JavaScript in the context of an authenticated user session.
date: "2026-10-25T16:45:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-based verification complete
tags:
  - xss
  - web-vulnerability
vendors:
  - LibreNMS
products:
  - LibreNMS (<= 24.9.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A reflected Cross-Site Scripting vulnerability allows remote attackers to inject arbitrary JavaScript code in the browsers of authenticated LibreNMS users through specially crafted URLs.
    confidence_band: high
cves:
  - id: CVE-2025-66850
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOELATPLAY-CVE-2025-66850
  - https://github.com/joelatplay/CVE-2025-66850
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOELATPLAY-CVE-2025-66850&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2025-66850 Exploitation Attempt
    description: Detects exploitation attempts against the LibreNMS routing module by searching for script tags in the protocol parameter
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade LibreNMS to version 24.10.0 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability was silently patched in version 24.10.0
  hunt_leads:
    - lead: Identify past exploitation attempts by scanning web access logs for common XSS patterns in the /routing endpoint
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The security flaw results from insufficient input validation in the /routing endpoint
  mitigation_plan:
    - priority: immediate
      action: Upgrade LibreNMS to 24.10.0
      owner: IT Operations
      addresses: CVE-2025-66850
      evidence: Fixed version 24.10.0 (November 5, 2024)
---

CVE-2025-66850 is a reflected Cross-Site Scripting (XSS) vulnerability in the LibreNMS routing module. The vulnerability exists within the 'protocol' parameter of the '/routing' endpoint. Insufficient input validation and the failure to perform HTML entity encoding allow an attacker to inject and execute arbitrary JavaScript in the browser of an authenticated user. This vulnerability affects LibreNMS versions up to and including 24.9.1. An undocumented fix was included in version 24.10.0.

## Impact

Successful exploitation allows a remote attacker to execute malicious scripts in the victim's browser session. Observed and theoretical impacts include the harvesting of session cookies, creation of unauthorized administrative accounts, or redirection of users to attacker-controlled domains.

## Recommendation

- Patch LibreNMS instances by upgrading to version 24.10.0 or later immediately.
- Review web server access logs for requests containing script tags or common XSS payloads targeting the '/routing' endpoint.
- Audit sessions of administrative users if the environment remained unpatched.
