---
brief_id: brief-2026-10-25-zenariocms-xss
event_id: brief-2026-10-25-zenariocms-xss
revision: 1
activity_at: "2026-10-25T08:40:43Z"
title: 'Tribalsystems Zenario CMS: Reflected XSS (CVE-2023-44770)'
slug: 2026-10-zenariocms-xss
description: A reflected cross-site scripting (XSS) vulnerability in the Zenario CMS Organizer spare alias feature allows authenticated users to execute arbitrary JavaScript within the administrative interface.
date: "2026-10-25T08:40:43Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:tribalsystems:zenario:9.4.59197:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - cms
vendors:
  - Tribalsystems
products:
  - Zenario (9.4.59197)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Cross Site Scripting vulnerability in ZenarioCMS v.9.4.59197 allows a local attacker to execute arbitrary code via a crafted script to the Organizer - Spare alias.
    confidence_band: high
cves:
  - id: CVE-2023-44770
    cvss: 5.4
    epss: 0.00591
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SROMANHU-CVE-2023-44770_ZENARIOCMS--REFLECTED-XSS---ORGANIZER-ALIAS
  - https://zenar.io/
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SROMANHU-CVE-2023-44770_ZENARIOCMS--REFLECTED-XSS---ORGANIZER-ALIAS&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all deployments of Zenario CMS 9.4.59197.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects specific version 9.4.59197.
  hunt_leads:
    - lead: Identify abnormal POST requests to the Organizer management module containing HTML/JavaScript payloads in the spare alias field.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Application audit logs for Zenario CMS
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Payload requires modification of the Organizer spare alias field.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest secure version of Zenario CMS.
      owner: IT Operations
      addresses: CVE-2023-44770
      evidence: Vulnerability is limited to version 9.4.59197.
---

CVE-2023-44770 is a reflected cross-site scripting (XSS) vulnerability affecting Tribalsystems Zenario CMS version 9.4.59197. The vulnerability exists due to insufficient input sanitization within the "Organizer - Spare alias" configuration field. An authenticated user can inject arbitrary JavaScript, which executes in the context of the administrative session when accessed.

## Impact
Successful exploitation allows for the execution of arbitrary JavaScript within the administrative panel. This could lead to session hijacking, unauthorized administrative actions, or the modification of site content, depending on the privileges of the victim viewing the malicious alias.

## Recommendation
- Audit Zenario CMS instances to identify if version 9.4.59197 is in use.
- Apply security patches or updates provided by Tribalsystems to remediate the vulnerability.
- Implement a Content Security Policy (CSP) to mitigate the impact of reflected XSS attacks in the administrative interface.
- Monitor administrative logs for suspicious modifications to Organizer settings or aliases.
