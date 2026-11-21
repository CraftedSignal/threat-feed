---
brief_id: brief-2026-07-nukeviet-xss-bypass
event_id: brief-2026-07-nukeviet-xss-bypass
revision: 2
activity_at: "2026-11-21T20:53:36Z"
revision_history:
  - revision: 2
    at: "2026-11-21T20:53:36Z"
    checksum: sha256:885277f65fc99984bad3e415d177ae4202c1bb740b6d5fce8dee9692378a0688
    summary: added coverage for NukeViet CMS (< 4.5.09)
    changed_fields:
      - action_plan
      - affected_products
      - content
      - cpes
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - qa_status
      - references
      - source_assessment
      - summary
      - title
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-54064
title: 'NukeViet CMS: Persistent Cross-Site Scripting (CVE-2026-54064)'
slug: 2026-07-nukeviet-xss-bypass
description: NukeViet CMS versions prior to 4.5.09 are vulnerable to persistent XSS, allowing authenticated users with news-posting permissions to bypass filter sanitization and execute arbitrary JavaScript in the context of other users.
date: "2026-07-13T17:58:46Z"
lastmod: "2026-11-21T20:52:36Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:vinades:nukeviet_cms:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - cms
  - cross-site-scripting
  - filter-bypass
vendors:
  - Vinades
products:
  - NukeViet
  - NukeViet CMS
product_versions:
  - product: NukeViet
    range: < 4.6.00
  - product: NukeViet CMS
    range: < 4.5.09
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.007
    subtechnique_name: JavaScript
    evidence: 'allows a low-privileged user (any account with news post permission) to store and serve arbitrary JavaScript to any visitor of the affected page. Proof-of-concept payload (URL-encoded POST body field `bodyhtml`): `<img src="x" %0Conerror="alert(''XSS'')">`'
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: This enables session cookie theft, credential harvesting, defacement, and further privilege escalation.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: NukeViet CMS is a multi Content Management System... a user with news-posting permission can bypass NukeViet\Core\Request::filterAttr() by prefixing an event-handler attribute with an ASCII form-feed character.
cves:
  - id: CVE-2026-54064
    cvss: 8.7
    epss: 0.00547
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-465g-4q99-5x86
  - https://cwe.mitre.org/data/definitions/79.html
  - https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting
  - https://owasp.org/Top10/A03_2021-Injection/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54064
  - https://cveawg.mitre.org/api/cve/CVE-2026-54064
action_plan:
  priority: elevated
  hunt_leads:
    - lead: 'Identify news-posting users submitting content containing ASCII form-feed characters (hex 0x0C) or decimal HTML entity tabs within HTML tag attributes, targeting event handlers (e.g., onclick, onload) or javascript: URIs.'
      technique_id: T1190
      data_needed:
        - web_server_access_logs
        - application_input_payloads
        - cms_database_content_audit
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: 'NukeViet CMS is a multi Content Management System... a user with news-posting permission can bypass NukeViet\Core\Request::filterAttr() by prefixing an event-handler attribute with an ASCII form-feed character... NukeViet\Core\Request::unhtmlentities() omitted a decimal HTML entity tab embedded in a javascript: URI.'
  mitigation_plan:
    - priority: immediate
      action: Upgrade NukeViet CMS to version 4.5.09 or later
      evidence: This issue is fixed in version 4.5.09.
  gaps:
    - No vendor-provided Sigma rules; hunting relies on web server access logs for anomalous input patterns.
updates:
  - at: "2026-11-21T20:52:36Z"
    level: L2
    summary: added coverage for NukeViet CMS (< 4.5.09)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-54064
---

## Overview
NukeViet CMS versions prior to 4.5.09 contain an input validation vulnerability in the `NukeViet\Core\Request::filterAttr()` and `NukeViet\Core\Request::unhtmlentities()` functions. Authenticated users with news-posting permissions can bypass security filters by injecting ASCII form-feed characters or decimal HTML entity tabs into event-handler attributes or `javascript:` URIs. These inputs are processed differently by the server-side sanitization and client-side browsers, allowing for the persistence and execution of arbitrary scripts. This vulnerability allows an attacker to execute JavaScript in the browser context of other users, including administrators, which may lead to account takeover or session hijacking.

## Impact
Successful exploitation results in persistent cross-site scripting (XSS) within the CMS, allowing unauthorized script execution for any user viewing the compromised content, including high-privileged administrator accounts.

## Recommendation
Upgrade NukeViet CMS to version 4.5.09 or later immediately to resolve the identified sanitization flaws in `vendor/vinades/nukeviet/Core/Request.php`.
