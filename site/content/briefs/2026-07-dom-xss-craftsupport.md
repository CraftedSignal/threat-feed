---
title: 'Craft CMS: DOM XSS via GitHub issue title in CraftSupport widget'
slug: 2026-07-dom-xss-craftsupport
description: An attacker with only a GitHub account can plant a malicious JavaScript payload in a GitHub issue title, leading to a DOM Cross-Site Scripting (XSS) vulnerability (CVE-2026-55790) that executes in a Craft CMS administrator's control panel session when they use the CraftSupport widget and retrieve the poisoned issue, allowing for arbitrary JavaScript execution and potential unauthorized actions.
date: "2026-07-06T21:34:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - craft-cms
  - application-layer
vendors:
  - Craft CMS
products:
  - Craft CMS 5.x (< 5.9.22)
  - Craft CMS 4.x (< 4.17.15)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: When a Craft admin uses the CraftSupport widget’s 'Give feedback' screen and types a search term that returns the poisoned issue, the payload executes in the admin’s control panel session.
    confidence_band: high
cves:
  - id: CVE-2026-55790
    epss: 0.00311
references:
  - https://github.com/advisories/GHSA-24x4-j6x9-rfw5
  - https://github.com/craftcms/cms/commit/6bbb66038a268552180ca5c8eed9f46ea25a4417
iocs:
  - type: url
    value: https://github.com/craftcms/cms/issues/new
ioc_counts:
  url: 1
---

A DOM Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-55790, has been identified in Craft CMS versions prior to 5.9.22 and 4.17.15, impacting the CraftSupport widget. This flaw allows an attacker to inject and execute arbitrary JavaScript code within a Craft CMS administrator's browser session. The attack vector involves an attacker, requiring only a GitHub account and no prior access to the Craft CMS control panel, planting a JavaScript payload within the title of a GitHub issue on the `craftcms/cms` repository. When a Craft CMS administrator accesses the CraftSupport widget's "Give feedback" screen and searches for a term that returns the attacker-controlled issue, the unsanitized issue title is rendered, causing the malicious payload to execute. This vulnerability is critical as it grants the attacker the ability to perform actions within the administrator's authenticated session.

## Attack Chain

1.  **Attacker creates malicious GitHub issue**: An attacker, using a standard GitHub account, navigates to `https://github.com/craftcms/cms/issues/new`.
2.  **Payload injection**: The attacker crafts a new issue title that combines a plausible search term with a JavaScript payload, e.g., `<img src=x onerror=alert(document.domain)> cannot upload files`.
3.  **Issue submission**: The attacker submits the crafted GitHub issue to the `craftcms/cms` repository.
4.  **Victim accesses Craft CMS dashboard**: A Craft CMS administrator logs into their control panel dashboard.
5.  **Victim opens CraftSupport widget**: The administrator opens the CraftSupport widget, typically located on the dashboard.
6.  **Victim triggers search**: The administrator clicks "Give feedback" within the widget and types a search term (e.g., `cannot upload files`) into the search box that matches the attacker's poisoned GitHub issue title.
7.  **Client-side rendering and XSS execution**: The CraftSupport widget's JavaScript (`CraftSupportWidget.js`) fetches the GitHub issue data. The `FeedbackScreen.getSearchResultText` function returns the issue title verbatim, which is then rendered via jQuery's `html:` option, leading to immediate execution of the injected JavaScript payload (e.g., `alert(document.domain)`) in the admin's browser session.
8.  **Post-XSS actions**: The executed JavaScript can access the administrator's session context, including CSRF tokens (`Craft.csrfTokenName`, `Craft.csrfTokenValue`), allowing the attacker to send same-origin requests and perform unauthorized actions within the Craft CMS control panel.

## Impact

Successful exploitation of this DOM XSS vulnerability results in arbitrary JavaScript execution within the targeted Craft CMS administrator's authenticated session. This grants the attacker the ability to perform any action the administrator can, including but not limited to, modifying settings, installing malicious plugins, exfiltrating data, or creating new administrative users. The attacker can leverage the victim's session and automatically obtained CSRF tokens to bypass protections and send authenticated requests. While the attacker relies on the administrator actively using a specific search function, the potential for full administrative compromise poses a significant risk to the integrity and confidentiality of the Craft CMS instance.

## Recommendation

*   **Patch CVE-2026-55790 immediately**: Upgrade affected Craft CMS instances to version 5.9.22 or later for Craft CMS 5.x, or 4.17.15 or later for Craft CMS 4.x.
*   **Educate administrators**: Advise Craft CMS administrators to exercise caution when interacting with embedded widgets that fetch external content, especially if search terms are user-controlled and results are displayed without obvious sanitization.
