---
brief_id: brief-2026-10-10-hivepress-xss
event_id: brief-2026-10-10-hivepress-xss
revision: 2
activity_at: "2026-10-10T09:52:06Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:dda5cb98461341ec5c79591a01c6a1050ba650952036d2f9c97d922e2e2602ff
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Stored XSS in HivePress WordPress Plugin
slug: 2026-10-10-hivepress-xss
description: The HivePress WordPress plugin for versions 1.7.31 and below contains a stored Cross-Site Scripting (XSS) vulnerability that allows unauthenticated attackers to execute arbitrary scripts in the context of user profiles.
date: "2026-10-10T09:52:06Z"
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
  validation_status: Source verified; no IOCs or specific log behavior documented
cpes:
  - cpe:2.3:a:hivepress:hivepress:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - wordpress
vendors:
  - HivePress
products:
  - HivePress (<= 1.7.31)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-107657
    cvss: 7.2
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107657
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade HivePress plugin to the latest version, which contains a fix for CVE-2026-107657
      owner: IT Operations
      addresses: CVE-2026-107657
      evidence: NVD vulnerability disclosure
---

The HivePress plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in all versions up to and including 1.7.31. The vulnerability exists due to insufficient input sanitization and output escaping of custom user attribute fields. An unauthenticated attacker can exploit this flaw if an administrator has configured a text-type custom user attribute using a display format that places the %value% variable inside an HTML attribute context, such as an 'href' attribute in an anchor tag. When front-end user profiles are enabled, the attacker can submit malicious JavaScript payloads into these fields. Once saved, these scripts execute in the browser of any user or administrator who views the injected user profile page. This can lead to unauthorized actions, session hijacking, or redirection, depending on the victim's privileges.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript within the session of a victim viewing a profile page. This can result in session token theft, the performance of actions on behalf of the victim (including administrative actions if the victim is an administrator), and account takeover, significantly impacting the integrity and confidentiality of the affected WordPress site.

## Recommendation

Update the HivePress plugin to a version released after 1.7.31 immediately. If an update is not immediately available, disable front-end user profile displays or remove custom user attributes that are configured with the %value% variable inside HTML attributes until a patch is applied.
