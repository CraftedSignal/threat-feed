---
brief_id: brief-2026-10-29-social-web-suite-sqli
event_id: brief-2026-10-29-social-web-suite-sqli
revision: 1
activity_at: "2026-10-29T05:03:29Z"
title: 'Social Web Suite: SQL injection and authentication bypass (CVE-2026-93904)'
slug: 2026-10-social-web-suite-sqli
description: The Social Web Suite WordPress plugin (up to 4.1.12) is vulnerable to unauthenticated SQL injection via the exclude_posts parameter and an authentication bypass due to insecure default HMAC secret key handling.
date: "2026-10-29T05:03:29Z"
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
  validation_status: Source-derived findings confirmed.
cpes:
  - cpe:2.3:a:social_web_suite:social_media_auto_post_social_media_auto_publish:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - sqli
  - authentication-bypass
vendors:
  - Social Web Suite
products:
  - Social Media Auto Post, Social Media Auto Publish (<= 4.1.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries.
    confidence_band: high
cves:
  - id: CVE-2026-93904
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93904
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Social Web Suite plugin to a version > 4.1.12
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects versions up to 4.1.12
  hunt_leads:
    - lead: Identify unauthenticated HTTP POST requests targeting the plugin API containing common SQL injection payloads
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability exists in the exclude_posts parameter via insufficient escaping
  mitigation_plan:
    - priority: immediate
      action: Upgrade Social Web Suite to the latest patched version
      owner: IT Operations
      addresses: CVE-2026-93904
      evidence: Plugin vulnerable up to and including 4.1.12
---

The Social Web Suite plugin for WordPress, versions 4.1.12 and earlier, contains a critical SQL injection vulnerability in the 'exclude_posts' parameter. This is caused by insufficient input escaping and lack of parameterized queries. Furthermore, the plugin is vulnerable to an authentication bypass on newly installed instances where the administrator has not yet initialized the settings. In this state, the HMAC secret key is empty, allowing attackers to forge valid authentication tokens using a known hash calculation.

## Impact

Unauthenticated attackers can extract sensitive data from the underlying WordPress database via the SQL injection vector. The authentication bypass enables attackers to reach protected endpoints without authorization.

## Recommendation

- Update the "Social Web Suite - Social Media Auto Post, Social Media Auto Publish" plugin to the latest patched version immediately.
- Until a patch is applied, audit the plugin settings page for newly installed instances to ensure the HMAC secret key has been lazily generated.
- Monitor web access logs for anomalous SQL syntax or repetitive POST requests targeting the plugin settings or API endpoints.
