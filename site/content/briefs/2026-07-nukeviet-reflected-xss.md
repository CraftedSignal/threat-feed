---
brief_id: brief-2026-07-nukeviet-reflected-xss
event_id: brief-2026-07-nukeviet-reflected-xss
revision: 1
activity_at: "2026-07-13T17:24:03Z"
title: 'NukeViet CMS: Comment module cross-site scripting (CVE-2026-48118)'
slug: 2026-07-nukeviet-reflected-xss
description: NukeViet CMS prior to version 4.5.09 is vulnerable to reflected cross-site scripting (XSS) via the status_comment parameter, allowing unauthenticated attackers to execute arbitrary JavaScript in a victim's session due to insecure security token derivation.
date: "2026-07-13T17:24:03Z"
lastmod: "2026-11-21T20:52:33Z"
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
cpes:
  - cpe:2.3:a:nukeviet:cms:*:*:*:*:*:*:*:*
tags:
  - nukeviet
  - xss
  - web-vulnerability
  - reflected-xss
  - credential-theft
  - vulnerability-exploitation
vendors:
  - NukeViet
products:
  - NukeViet CMS
product_versions:
  - product: NukeViet CMS
    range: < 4.5.09
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Exploitable remotely via crafted URL
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: JavaScript executes in victim's browser
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: Attacker delivers the following URL to the victim
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: access to cookies, session storage, and the ability to make authenticated requests
    confidence_band: high
cves:
  - id: CVE-2026-48118
    cvss: 8.2
    epss: 0.00684
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-mxpf-qgg6-v3ff
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48118
  - https://cveawg.mitre.org/api/cve/CVE-2026-48118
action_plan:
  priority: elevated
  hunt_leads:
    - lead: Search web access logs for requests targeting 'modules/comment/funcs/main.php' or 'modules/comment/comment.php' where the 'status_comment' parameter contains encoded strings. Cross-reference these entries with public comment activity on the site to identify tokens derived from 'NV_CACHE_PREFIX' that appear in web logs rather than session-bound markers.
      technique_id: T1190
      data_needed:
        - web server access logs
        - HTTP request parameters
        - HTTP request URI
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated attacker can therefore cause decoded HTML or JavaScript to render in a victim's browser and perform phishing or same-origin actions.
  mitigation_plan:
    - priority: immediate
      action: Upgrade NukeViet CMS to version 4.5.09 or later
      evidence: This issue is fixed in version 4.5.09.
  gaps:
    - No specific vendor-provided Sigma rule or WAF signature available for this XSS vector.
updates:
  - at: "2026-11-21T20:52:33Z"
    level: L2
    summary: added coverage for NukeViet CMS (< 4.5.09)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48118
---

## Overview
NukeViet CMS is a multi-purpose Content Management System. A vulnerability exists in the Comment module where the status_comment parameter in modules/comment/funcs/main.php accepts attacker-controlled base64 content. The module decodes this content using nv_base64_decode() and assigns it to STATUS_COMMENT without proper output escaping in modules/comment/comment.php. Additionally, the required checkss token is derived from the site-wide NV_CACHE_PREFIX instead of NV_CHECK_SESSION. This implementation flaw allows a token disclosed in public comment markup to be reused across sessions in a crafted URL. An unauthenticated attacker can exploit this to render malicious HTML or execute arbitrary JavaScript in the browser of a victim, facilitating phishing or same-origin attacks.

## Impact
Successful exploitation allows unauthenticated attackers to perform reflected XSS, enabling them to execute arbitrary JavaScript within a victim's browser session. This can lead to session hijacking, unauthorized actions performed on behalf of the user, or phishing campaigns. The vulnerability is rated at CVSS 8.2 (High) due to the potential for unauthorized data access and session-based manipulation.

## Recommendation
Upgrade NukeViet CMS to version 4.5.09 or later to remediate this vulnerability. Organizations using earlier versions should immediately inventory all instances of NukeViet CMS and apply the patch. As this is a reflected XSS issue, consider monitoring web access logs for requests containing suspicious base64-encoded patterns in the status_comment parameter.
