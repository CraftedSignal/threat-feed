---
title: Capacitor WebView Navigation Guard Bypass
slug: 2026-10-capacitor-webview-rce
description: A flaw in the Capacitor WebView navigation guard allows attackers to force in-app navigation to an internal proxy path, enabling the execution of arbitrary remote content within the application's origin.
date: "2026-10-06T00:42:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - mobile
  - webview
  - cve-2026-103922
vendors:
  - Ionic
products:
  - Capacitor Android (>= 6.0.0, < 6.2.2; >= 7.0.0, < 7.6.9; >= 8.0.0, <= 8.3.4; >= 8.3.5, < 8.4.3; >= 8.5.0, < 8.5.1)
  - Capacitor iOS (>= 6.0.0, < 6.2.2; >= 7.0.0, < 7.6.9; >= 8.0.0, <= 8.3.4; >= 8.3.5, < 8.4.3; >= 8.5.0, < 8.5.1)
  - capacitor-swift-pm (>= 6.0.0, < 6.2.2; >= 7.0.0, < 7.6.9; >= 8.0.0, <= 8.3.4; >= 8.3.5, < 8.4.3; >= 8.5.0, < 8.5.1)
  - com.capacitorjs:core (>= 6.0.0, < 6.2.2; >= 7.0.0, < 7.6.9; >= 8.0.0, <= 8.3.4; >= 8.3.5, < 8.4.3; >= 8.5.0, < 8.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Exploitation requires a victim to activate a link inside the application's WebView.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: JavaScript
    evidence: Script in that response then ran with full same-origin trust.
    confidence_band: high
cves:
  - id: CVE-2026-103922
    cvss: 9.3
    epss: 0.00213
references:
  - https://github.com/advisories/GHSA-rvm3-566m-v7fv
action_plan:
  priority: immediate_escalation
  owners:
    - Mobile Development Team
    - Security Engineering
  immediate_actions:
    - action: Upgrade Capacitor packages to fixed versions 6.2.2, 7.6.9, 8.4.3, or 8.5.1.
      owner: Mobile Development Team
      due: 24h
      evidence: Source advisory specifies patched versions.
  mitigation_plan:
    - priority: immediate
      action: Override WebView navigation methods (shouldOverrideLoad) to block /_capacitor_http_interceptor_ path.
      owner: Mobile Development Team
      addresses: CVE-2026-103922
      evidence: Source provides mitigation code logic.
---

Ionic's Capacitor framework contains a critical vulnerability (CVE-2026-103922) affecting both Android and iOS platforms. The vulnerability stems from an insufficient validation process within the WebView navigation guard, which only checked the host and scheme of a URL, ignoring the path component. This allowed attackers to route navigation to the internal HTTP proxy path (`/_capacitor_http_interceptor_`), which is served by the application's origin regardless of the `CapacitorHttp` plugin status.

When an attacker forces the application to load this path as a document, the native layer fetches arbitrary content and injects it into the WebView as same-origin content. This grants the injected script access to `localStorage`, cookies, and all exposed native Capacitor plugins. Any Capacitor-based application that renders user-supplied links or rich-text content is susceptible to this attack, which effectively elevates remote attacker control to the level of the application's internal trust.

## Attack Chain

1. Attacker identifies a Capacitor-based application that renders user-controlled input (e.g., chat messages, comments).
2. Attacker crafts a malicious URL pointing to the application's internal proxy path (`/_capacitor_http_interceptor_`).
3. Attacker injects this URL into the application via the identified input vector.
4. Victim clicks the link within the application's WebView.
5. The Capacitor navigation guard evaluates the URL, observes the correct host and scheme, and permits the navigation.
6. The native proxy handler intercepts the request for `/_capacitor_http_interceptor_` and fetches the attacker's malicious remote content.
7. The WebView renders the malicious content within the app's origin, granting the attacker full access to local storage, cookies, and sensitive native plugins.

## Impact

The vulnerability allows an attacker to execute arbitrary scripts with same-origin privileges. Successful exploitation results in the unauthorized exfiltration of sensitive data, such as session cookies and locally stored information. Furthermore, attackers can leverage the application's registered native plugins to perform unauthorized actions on the user's device, significantly impacting the integrity and confidentiality of any Capacitor-powered mobile application.

## Recommendation

Prioritized, concrete actions for engineering and security teams:

- Upgrade Capacitor Android, iOS, and Core components to versions 6.2.2, 7.6.9, 8.4.3, or 8.5.1 to remediate CVE-2026-103922.
- Implement an immediate block in the native navigation layer to cancel any navigation to paths starting with `/_capacitor_http_interceptor_` if an immediate upgrade is not possible.
- Audit and sanitize all user-controlled link targets rendered within the WebView to prevent malicious navigation attempts.
