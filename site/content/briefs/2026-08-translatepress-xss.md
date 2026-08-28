---
title: Stored Cross-Site Scripting in TranslatePress WordPress Plugin
slug: 2026-08-translatepress-xss
description: The TranslatePress plugin for WordPress is vulnerable to unauthenticated stored XSS through improper sanitization of comment data, allowing attackers to inject persistent malicious scripts.
date: "2026-08-28T07:12:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - xss
  - wordpress
vendors:
  - TranslatePress
products:
  - Translate Multilingual sites with AI Translation (3.3.3)
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
    evidence: Exploitation is possible because WordPress's comment KSES allowlist permits the payload structure... causing the malicious comment to be stored verbatim in the database.
    confidence_band: high
cves:
  - id: CVE-2026-76053
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76053
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Update TranslatePress plugin to version 3.3.4 or later
      owner: IT Operations
      due: 24h
      evidence: Plugin version 3.3.3 and below are vulnerable to CVE-2026-76053
---

TranslatePress versions 3.3.3 and below for WordPress contain a stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-76053). The flaw arises from insufficient input sanitization and output escaping within the plugin's translation parser. An unauthenticated attacker can exploit WordPress comment KSES allowlist configurations by injecting a crafted combination of anchor tags (href and title attributes) and code tags. This payload bypasses standard filters and is stored directly in the WordPress database. When the plugin processes these comments for page translation, the injected scripts are rendered and executed in the browser of any user viewing the page. This vulnerability poses a significant risk to site administrators and users, as it can be used for session hijacking, credential theft, or unauthorized actions performed on behalf of the victim.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of the victim's session. This can lead to full site compromise if administrative sessions are targeted, unauthorized modifications to site content, or the theft of sensitive user data from affected pages.

## Recommendation

Update the TranslatePress plugin to version 3.3.4 or higher immediately to remediate the sanitization deficiency. Ensure that standard WordPress commenting permissions are restricted to authenticated users where possible to reduce the attack surface for unauthenticated exploitation. If updating is not immediately feasible, disable the plugin's translation feature for public comment sections.
