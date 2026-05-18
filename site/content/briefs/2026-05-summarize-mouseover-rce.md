---
title: Summarize Extension Mouseover Authenticated Request Vulnerability (CVE-2026-45245)
slug: 2026-05-summarize-mouseover-rce
description: Summarize versions prior to 0.15.1 contain a vulnerability (CVE-2026-45245) in the hover summary feature that allows malicious pages to dispatch synthetic mouseover events, triggering authenticated daemon requests and potentially exposing sensitive internal endpoints.
date: "2026-05-18T20:18:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-45245
  - browser-extension
  - authenticated-request-forgery
  - mouseover-event
vendors:
  - Summarize
products:
  - Summarize < 0.15.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-45245
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45245
rules:
  - title: Detect Summarize Extension Synthetic Mouseover Event
    description: Detects CVE-2026-45245 exploitation — potential synthetic mouseover events targeting local or private network addresses, indicating an attempt to exploit the Summarize extension vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect Summarize Extension Local File Access
    description: Detects CVE-2026-45245 exploitation — potential local file access attempts through Summarize extension by monitoring requests containing file:// scheme.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

Summarize, a browser extension, is vulnerable to an authenticated request forgery via synthetic mouseover events. Prior to version 0.15.1, the extension's hover summary feature fails to validate the trustworthiness of mouseover events. This allows a malicious webpage to dispatch synthetic events over attacker-controlled links. Consequently, the extension makes authenticated daemon requests using stored tokens, potentially routing these requests to local or private-network URLs. This vulnerability, identified as CVE-2026-45245, could enable attackers to access sensitive internal endpoints when users interact with malicious content through the extension.

## Attack Chain

1.  Attacker crafts a malicious webpage containing attacker-controlled links.
2.  The malicious webpage uses JavaScript to dispatch synthetic `mouseover` events targeting the attacker-controlled links.
3.  The Summarize extension's hover summary feature processes the synthetic `mouseover` event without proper validation.
4.  The extension generates an authenticated request to the daemon, based on the link targeted by the `mouseover` event.
5.  The attacker-controlled link points to a local or private network URL.
6.  The extension routes the authenticated request to the specified local or private network URL.
7.  If the local or private network URL corresponds to an internal endpoint without proper authorization checks, the attacker may gain unauthorized access.
8.  Successful exploitation allows the attacker to read sensitive information from the internal endpoint.

## Impact

Successful exploitation of CVE-2026-45245 can allow attackers to access sensitive internal endpoints through a user's Summarize extension. By placing local or private-network URLs behind hoverable links, attackers can route authenticated requests through the daemon, bypassing network security measures. The impact includes unauthorized access to internal resources and potential data exfiltration.

## Recommendation

*   Upgrade the Summarize extension to version 0.15.1 or later to remediate CVE-2026-45245.
*   Deploy the Sigma rule "Detect Summarize Extension Synthetic Mouseover Event" to identify potential exploitation attempts.
*   Educate users about the risks of interacting with untrusted webpages and the potential for malicious mouseover events.
