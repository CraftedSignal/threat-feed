---
title: Stored DOM-Based XSS in Molongui Authorship WordPress Plugin
slug: 2026-10-molongui-xss
description: The Molongui Authorship plugin is vulnerable to unauthenticated Stored DOM-based XSS via unsanitized href attributes in comment content, enabling arbitrary script execution in victim browsers.
date: "2026-10-10T09:51:27Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:molongui:molongui_authorship_-_author_boxes,_guest_authors_&_co-authors:*:*:*:*:*:wordpress:*:*
vendors:
  - Molongui
products:
  - Molongui Authorship – Author Boxes, Guest Authors & Co-Authors (<= 5.2.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-101920
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101920
action_plan:
  priority: elevated
  owners:
    - SOC
    - Web Operations
  immediate_actions:
    - action: Inventory instances of Molongui Authorship plugin and update to version > 5.2.12.
      owner: Web Operations
      due: 24h
      evidence: CVE-2026-101920 vulnerability applies to <= 5.2.12.
  mitigation_plan:
    - priority: immediate
      action: Disable comment functionality on sites using affected plugin versions.
      owner: Web Operations
      addresses: CVE-2026-101920
      evidence: Exploitation occurs via comment input vectors.
---

The Molongui Authorship - Author Boxes, Guest Authors & Co-Authors plugin for WordPress is affected by a stored DOM-based Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-101920. The flaw stems from insufficient input sanitization and output escaping when handling the 'href' attribute within comment content. 

The vulnerability is present in all versions up to and including 5.2.12. An unauthenticated attacker can exploit this by injecting malicious scripts into comment fields. The exploitation is facilitated by a logic flaw in the plugin's author-filter rewriter. Because the plugin's 'has_pro()' function returns false for the free version, the rewriter fails to append the '?m_bm=true' marker to anchors. Consequently, the byline script inadvertently selects and processes attacker-controlled 'href' attributes, leading to execution in the context of any user viewing the page. This vulnerability poses a significant risk to WordPress site integrity and user session security.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of other users visiting the affected pages. This can lead to session hijacking, unauthorized actions performed on behalf of authenticated users (including administrative accounts), and the defacement of the affected WordPress site. The vulnerability affects any site running the free version of the Molongui Authorship plugin (versions 5.2.12 and earlier).

## Recommendation

* Update the 'Molongui Authorship - Author Boxes, Guest Authors & Co-Authors' plugin to the latest version immediately once a patch is released by the vendor.
* Disable comments globally or on posts containing authorship bylines if an update cannot be applied immediately to prevent active exploitation of the input vector.
* Review web server logs for HTTP POST requests to comment submission endpoints that contain script-like content or suspicious 'href' attributes within comment data.
* Implement a Content Security Policy (CSP) to restrict the execution of inline scripts and unauthorized external resources, mitigating the impact of successful XSS injections.
