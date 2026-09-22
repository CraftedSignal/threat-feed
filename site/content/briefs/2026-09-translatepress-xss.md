---
title: Stored Cross-Site Scripting in TranslatePress WordPress Plugin
slug: 2026-09-translatepress-xss
description: The TranslatePress plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the Translation Memory Suggestion Panel, allowing unauthenticated attackers to execute arbitrary scripts in administrator sessions.
date: "2026-09-22T08:34:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:translatepress:translatepress:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-89412
vendors:
  - WordPress
products:
  - TranslatePress (<= 3.3.5)
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
    technique_name: JavaScript
    evidence: Unauthenticated attackers can seed the translation dictionary's original column with executable HTML because the front-end rendering pipeline decodes entity-encoded payloads.
    confidence_band: high
cves:
  - id: CVE-2026-89412
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89412
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Upgrade TranslatePress to version 3.3.6 or later.
      owner: IT Operations
      due: 24h
      evidence: Plugin version 3.3.5 and below are confirmed vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Upgrade TranslatePress to latest available version.
      owner: IT Operations
      addresses: CVE-2026-89412
      evidence: NVD vulnerability disclosure.
---

The TranslatePress - Translate Multilingual sites with AI Translation plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in all versions up to and including 3.3.5. The vulnerability stems from improper input sanitization and output escaping within the Translation Memory Suggestion Panel. Specifically, the plugin uses `html_entity_decode()` on input payloads before persistence into the database, and the relevant column is explicitly exempt from `kses` filtering. This allows unauthenticated attackers to inject malicious HTML and JavaScript into the translation dictionary. When an administrator later views the affected translation page, the payload is rendered via `v-html` and executed within their browser session. This flaw could lead to unauthorized administrative actions, session hijacking, or site-wide impact if the script performs further malicious operations.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of an administrator session. This can lead to full site compromise, unauthorized configuration changes, or the exfiltration of sensitive data, affecting any WordPress installation running the vulnerable TranslatePress version.

## Recommendation

Prioritize the update of the TranslatePress plugin to the latest version. Monitor web server access logs for anomalous POST requests directed at endpoints responsible for saving translation memory data. Review the site's WordPress installation for unauthorized modifications to translation dictionary tables. Ensure that Content Security Policy (CSP) headers are implemented to mitigate the impact of potential XSS attacks.
