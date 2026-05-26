---
title: Typebot Stored XSS via Rating Block Custom Icon
slug: 2026-05-typebot-xss
description: Typebot is vulnerable to stored cross-site scripting (XSS) due to the rating block's custom icon feature, which accepts arbitrary HTML/SVG via the `customIcon.svg` field without sanitization. When a malicious typebot is imported or crafted by a workspace collaborator, the payload executes in the builder's DOM context, bypassing the `isUnsafe` Web Worker sandbox that protects Script blocks during preview, allowing session hijacking and privilege escalation within the builder application.
date: "2026-05-26T17:40:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - stored-xss
  - web-application
  - typebot
vendors:
  - typebot
products:
  - '@typebot.io/js (< 0.10.1)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data From Local System
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
cves:
  - id: CVE-2026-28445
    cvss: 8.7
    epss: 0.00031
references:
  - https://github.com/advisories/GHSA-6m7c-xfhp-p9fh
  - CVE-2026-28445
rules:
  - title: Detect Typebot Rating Block XSS Attempt
    description: Detects a Typebot rating block XSS attempt by identifying suspicious SVG content within the custom icon field.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1547
    data_sources:
      - webserver
  - title: Detect Typebot Builder Session Hijacking via Cookie Exfiltration
    description: Detects potential session hijacking attempts in Typebot Builder by monitoring network connections for cookie exfiltration patterns.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - network_connection
rules_count: 2
---

Typebot is vulnerable to a stored cross-site scripting (XSS) vulnerability in the rating block's custom icon feature. The vulnerability stems from the lack of sanitization of the `customIcon.svg` field, which allows attackers to inject arbitrary HTML/SVG code. This code executes within the builder's DOM context, bypassing the `isUnsafe` Web Worker sandbox designed to protect against untrusted bots during preview. An attacker can exploit this by crafting a malicious typebot or by compromising a workspace collaborator account. Successful exploitation leads to session hijacking and privilege escalation within the builder application. This issue affects versions of `@typebot.io/js` prior to 0.10.1.

## Attack Chain

1. An attacker crafts a malicious typebot JSON file containing a rating block with a custom icon that includes XSS payload in the `customIcon.svg` field.
2. The attacker distributes the malicious typebot file through community forums, template marketplaces, or direct sharing with potential victims.
3. A victim imports the malicious typebot into their workspace within the Typebot builder application.
4. The victim previews the imported bot in the builder application, triggering the rendering of the malicious rating block.
5. The injected XSS payload within the `customIcon.svg` field executes directly in the builder's DOM, bypassing the `isUnsafe` Web Worker sandbox.
6. The XSS payload exfiltrates the victim's session cookies and authentication tokens from the builder origin (builder.typebot.io).
7. The attacker uses the stolen session tokens to gain unauthorized access to the victim's Typebot workspace.
8. The attacker can then modify bots, access integrations, and view collected data, leading to account takeover and further malicious activities.

## Impact

Successful exploitation of this XSS vulnerability can lead to session hijacking, privilege escalation, and account takeover within the Typebot builder application. An attacker can steal authentication cookies and session tokens, allowing them to access and modify the victim's workspace, including bots, integrations, and collected data. This can have severe consequences, including data breaches, unauthorized access to sensitive information, and disruption of normal business operations. The lack of sanitization in the rating block bypasses the existing `isUnsafe` sandbox, making imported and untrusted bots a significant security risk.

## Recommendation

*   Apply DOMPurify sanitization to the `customIcon.svg` content within the `RatingButton` component in `packages/embeds/js/src/features/blocks/inputs/rating/components/RatingForm.tsx` to neutralize any malicious HTML/SVG code.
*   Implement SVG-specific validation in the Zod schema or within the `sanitizeBlock` function in `apps/builder/src/features/typebot/helpers/sanitizers.ts` to prevent the storage of malicious content.
*   Audit other usages of `innerHTML` within the codebase, such as in `FileUploadForm.tsx:234`, for similar XSS vulnerabilities and implement appropriate sanitization measures.
*   Deploy the Sigma rule "Detect Typebot Rating Block XSS Attempt" to identify potential exploitation attempts targeting the custom icon feature.
