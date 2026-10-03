---
title: Stored XSS in The Real Cookie Banner WordPress Plugin
slug: 2026-10-real-cookie-banner-xss
description: The Real Cookie Banner plugin (<= 5.3.5) for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via inadequate input sanitization in comment anchor tags, allowing unauthenticated attackers to execute arbitrary scripts in the browser context of site visitors.
date: "2026-10-03T04:53:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:the_real_cookie_banner_gdpr_eprivacy_cookie_consent:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-92977
vendors:
  - WordPress
products:
  - 'The Real Cookie Banner: GDPR & ePrivacy Cookie Consent (<= 5.3.5)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: Malicious script payloads placed in the title attribute of an anchor tag survive WordPress's comment kses filter at save time.
    confidence_band: high
cves:
  - id: CVE-2026-92977
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92977
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Web Security
  immediate_actions:
    - action: Update The Real Cookie Banner plugin to the latest version.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-92977 indicates vulnerability in versions <= 5.3.5.
  mitigation_plan:
    - priority: immediate
      action: Enable strict comment moderation settings to review all incoming comments.
      owner: Web Security
      addresses: CVE-2026-92977
      evidence: Exploitability is subject to the standard comment moderation workflow.
---

The Real Cookie Banner: GDPR & ePrivacy Cookie Consent plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in all versions up to and including 5.3.5. The vulnerability stems from insufficient input sanitization and output escaping when handling content within comment anchor tags. Unauthenticated attackers can inject malicious payloads into the title attribute of these tags, which successfully bypass the default WordPress comment kses filter. 

The exploitation relies on the plugin's internal rendering logic, specifically a page-wide regex operation that strips the closing quote delimiter of the title attribute at render time. This transformation converts the payload from a benign attribute value into executable HTML. While the exploitation requires the injected comment to survive the site's standard comment moderation workflow, successful execution allows attackers to run arbitrary scripts in the session of any user viewing the page, potentially leading to session hijacking, site defacement, or administrative account compromise if viewed by privileged users.

## Attack Chain

1. Attacker crafts a malicious payload containing an XSS vector within the title attribute of an anchor tag (e.g., `<a title='x' onmouseover=alert(1) '>`).
2. Attacker submits the payload through the WordPress comment form.
3. The WordPress 'kses' filter processes the comment but fails to properly sanitize the title attribute of the anchor tag, allowing the payload to be saved to the database.
4. The malicious comment enters the site's moderation queue awaiting approval.
5. An administrator or moderator reviews and approves the malicious comment, moving it to a public-facing page.
6. A target user visits the page containing the malicious comment.
7. The Real Cookie Banner plugin processes the page, and its regex strips the closing quote delimiter of the title attribute.
8. The malicious script is rendered as valid HTML in the victim's browser and executes with the privileges of the victim's session.

## Impact

Successful exploitation of this vulnerability allows for the execution of arbitrary JavaScript in the context of the victim's browser session. If a site administrator views a page containing the malicious payload, the attacker could potentially perform actions on behalf of the administrator, lead to unauthorized configuration changes, or exfiltrate sensitive site data. The vulnerability affects any WordPress site running the vulnerable version of the Real Cookie Banner plugin that permits user comments.

## Recommendation

Prioritize the update of the Real Cookie Banner: GDPR & ePrivacy Cookie Consent plugin to the latest available version beyond 5.3.5 to mitigate CVE-2026-92977. Ensure that the WordPress comment moderation workflow is configured to require manual approval for all comments to prevent unauthenticated injection attempts from immediately becoming publicly visible. Conduct a review of recently approved comments for any suspicious anchor tag attributes.
