---
title: Stored Cross-Site Scripting in GSpeech TTS Plugin
slug: 2026-10-gspeech-xss
description: The GSpeech TTS plugin for WordPress (<= 3.22.0) is vulnerable to Stored Cross-Site Scripting via improper input sanitization and output-buffer manipulation, allowing unauthenticated attackers to execute arbitrary JavaScript.
date: "2026-10-02T10:23:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gspeech:gspeech_tts:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-vulnerability
  - wordpress
vendors:
  - GSpeech
products:
  - GSpeech TTS – WordPress Text To Speech Plugin (<= 3.22.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96578
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96578
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade GSpeech TTS plugin to a version later than 3.22.0
      owner: IT Operations
      due: 24h
      evidence: Source identifies 3.22.0 as the vulnerable version.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to latest version
      owner: IT Operations
      addresses: CVE-2026-96578
      evidence: Source identifies version 3.22.0 as vulnerable.
---

The GSpeech TTS - WordPress Text To Speech Plugin is vulnerable to Stored Cross-Site Scripting (XSS) in all versions up to and including 3.22.0. The vulnerability stems from insufficient input sanitization and output escaping within the comment processing logic. Attackers can inject payloads that successfully bypass WordPress comment kses sanitization by utilizing allowed tags and attributes. The payload undergoes a mutation-based cross-site scripting (mXSS) transformation when the plugin's output-buffer callback processes the stored content at render time. This allows malicious JavaScript to execute in the browser of any user viewing the page containing the injected comment. Given that this vulnerability allows unauthenticated access and potential session hijacking or further credential theft, it poses a significant risk to the integrity of WordPress-based web sites.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript within the context of a victim's session. This may lead to unauthorized actions performed on behalf of authenticated administrators, theft of session cookies, or the redirection of users to malicious external sites. All websites running GSpeech TTS version 3.22.0 or earlier are currently exposed to this threat.

## Recommendation

- Update the GSpeech TTS - WordPress Text To Speech Plugin to the latest available version beyond 3.22.0 to ensure the patch is applied.
- Audit existing comments on sites using the affected plugin for suspicious script tags or obfuscated HTML patterns that might indicate exploitation attempts.
- Implement a Content Security Policy (CSP) that restricts script execution to trusted domains to mitigate the impact of potential XSS vulnerabilities.
