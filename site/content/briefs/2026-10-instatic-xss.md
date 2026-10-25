---
brief_id: brief-2026-10-25-instatic-xss
event_id: brief-2026-10-25-instatic-xss
revision: 1
activity_at: "2026-10-25T05:40:26Z"
title: 'Instatic: Stored XSS via URL sanitization bypass (CVE-2026-103931)'
slug: 2026-10-instatic-xss
description: An incomplete URL sanitization routine in the Instatic isSafeUrl() function allows stored Cross-Site Scripting (XSS) via leading C0 control characters, enabling low-privileged users to achieve administrative account compromise.
date: "2026-10-25T05:40:26Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; remediation requires code update.
tags:
  - xss
  - web-security
  - cwe-79
  - sanitization-bypass
vendors:
  - Instatic
products:
  - Instatic (<= 0.0.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A public exploit or PoC has been published on Sploitus for CVE-2026-103931.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Privilege escalation from a low-privileged editor to full admin compromise.
    confidence_band: high
cves:
  - id: CVE-2026-103931
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OVERGROWNCARROT1-INSTATIC-STORED-XSS-CVE-2026-103931
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OVERGROWNCARROT1-INSTATIC-STORED-XSS-CVE-2026-103931&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Instatic to a version patched against CVE-2026-103931
      owner: IT Operations
      due: 48h
      evidence: Instatic v0.0.13 is confirmed vulnerable
  hunt_leads:
    - lead: Search for stored link attributes or markdown containing non-printable C0 control characters (ASCII 0x01-0x1F) in the database.
      technique_id: T1190
      data_needed:
        - Database records of site content, specifically link hrefs and image sources
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Payload uses leading C0 control characters to bypass isSafeUrl
  mitigation_plan:
    - priority: immediate
      action: 'Restrict the admin interface with a strict Content Security Policy (CSP) blocking javascript: and unsafe-inline execution.'
      owner: Application Security
      addresses: CVE-2026-103931
      evidence: The admin-origin execution reported document.domain as the serving origin.
---

Instatic version 0.0.13 and earlier are vulnerable to a Stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-103931) within the `isSafeUrl()` function located in `src/core/html-sanitize/index.ts`. The sanitization logic fails to correctly filter C0 control characters (U+0000 - U+001F) when checking for malicious URL schemes such as `javascript:`, `vbscript:`, or `data:`. Browsers strip these leading control characters during URL parsing, allowing payloads to bypass the application's security filter and execute in the context of the admin editor's same-origin frame.

## Attack Chain

1. An attacker with 'Client' role privileges (or any role capable of editing page content) crafts a malicious URL payload using leading C0 control characters (e.g., `\x01javascript:alert(document.domain)`).
2. The payload is submitted via a link `href`, `image` source, or custom HTML attribute field.
3. The `isSafeUrl()` function attempts to normalize the input but fails to remove the specific C0 control characters, incorrectly marking the payload as "safe".
4. The malicious link is stored in the site content database.
5. An administrator or owner opens the affected page within the admin editor canvas, which is an `srcdoc` iframe sharing the same origin as the `/admin` application.
6. Because the admin interface lacks a strict `script-src` Content Security Policy (CSP), the browser executes the `javascript:` payload within the admin origin upon interaction.
7. The payload executes with the privileges of the authenticated administrator, enabling session hijacking, account creation, or other malicious administrative actions.

## Impact

Successful exploitation allows a low-privileged editor to escalate privileges to full administrative compromise by executing arbitrary JavaScript in the admin editor's origin. On published sites, the risk is dependent on the CSP; pages utilizing `'unsafe-inline'` are vulnerable to execution of these filtered protocols.

## Recommendation

1. Upgrade Instatic to a version containing the fix that properly strips the full C0 and space range from URL inputs.
2. Implement a strict `script-src` Content Security Policy (CSP) for the admin interface to prevent the execution of inline scripts and `javascript:` protocol URLs.
3. Audit existing user-contributed content for links containing non-printable or unexpected control characters.
