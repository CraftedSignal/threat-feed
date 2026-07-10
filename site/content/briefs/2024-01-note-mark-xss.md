---
title: Note Mark Stored XSS via Unrestricted Asset Upload
slug: 2024-01-note-mark-xss
description: A stored same-origin XSS vulnerability in Note Mark allows an authenticated user to upload malicious HTML, SVG, or XHTML files as note assets, leading to arbitrary code execution in a victim's browser due to missing content type restrictions and resulting in potential access to private notes, books, and authenticated API actions.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-application
  - github
vendors:
  - Note Mark
products:
  - Note Mark
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
references:
  - https://github.com/advisories/GHSA-9pr4-rf97-79qh
rules:
  - title: Detect Note Mark Asset Upload with HTML Content
    description: Detects the upload of HTML content as a note asset in Note Mark, which may indicate a potential XSS attack.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Note Mark Asset Delivery Without nosniff
    description: 'Detects Note Mark asset delivery responses lacking the X-Content-Type-Options: nosniff header, which could allow MIME sniffing and XSS.'
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stored same-origin XSS vulnerability has been identified in Note Mark, specifically affecting versions prior to commit `6bb62842ccb9` on April 11, 2026. This vulnerability allows an authenticated user to upload a crafted HTML, SVG, or XHTML file as a note asset. Due to the application's failure to set a safe content type and lacking the `nosniff` header, a victim's browser can sniff the file and execute its active content. This gives the attacker the ability to execute JavaScript within the victim's authenticated session, potentially compromising private notes, books, profile data, and authenticated API actions. The vulnerability is triggered when a victim opens the malicious asset URL, requiring user interaction. This issue poses a significant risk to deployments allowing asset uploads, as it allows for cross-user data compromise.

## Attack Chain

1. An attacker obtains a valid user account on a Note Mark instance.
2. The attacker crafts a malicious HTML, SVG, or XHTML file containing XSS payload (e.g., `<script>fetch('/api/notes').then(r => r.json()).then(data => console.log(data))</script>`).
3. The attacker uploads the malicious file as a note asset using the Note Mark web interface or API, exploiting the unrestricted asset upload.
4. The Note Mark server stores the file without properly setting the `Content-Type` header (it defaults to empty).
5. The attacker crafts a URL pointing to the uploaded asset, using the `/api/notes/{noteID}/assets/{assetID}` endpoint.
6. The attacker distributes the malicious URL to a victim (e.g., via phishing or social engineering).
7. The victim clicks the link, causing their browser to request the asset.
8. The browser, due to the missing `Content-Type` and lack of `X-Content-Type-Options: nosniff`, sniffs the content as HTML/SVG and executes the embedded JavaScript in the victim's authenticated session, granting the attacker access to Note Mark API actions as the victim.

## Impact

Successful exploitation of this XSS vulnerability can have significant consequences. An attacker could potentially access or modify a victim's private notes, books, and profile data. Furthermore, the attacker could perform authenticated API actions on behalf of the victim, leading to further data breaches or unauthorized modifications. This vulnerability impacts any deployment allowing asset uploads and any user who can be induced to open a malicious asset URL.

## Recommendation

*   Upgrade to Note Mark version `0.0.0-20260411145018-6bb62842ccb9` or later to incorporate the patch that addresses this vulnerability (reference: Affected Packages in the overview).
*   Implement strict content type validation on asset uploads to ensure that only safe file types are allowed (related to Attack Chain step 3).
*   Configure the web server to send the `X-Content-Type-Options: nosniff` header for all responses to prevent browsers from MIME-sniffing responses (related to Attack Chain step 8).
*   Deploy the Sigma rule `Detect Note Mark Asset Upload with HTML Content` to identify potentially malicious asset uploads (reference: Sigma rule below).
*   Review and audit the asset delivery route (`handlers/assets.go:40`) to ensure proper security controls are in place.
