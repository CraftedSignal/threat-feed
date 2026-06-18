---
title: 'Kirby: Self cross-site scripting (self-XSS) in the writer field (CVE-2026-49276)'
slug: 2026-06-kirby-self-xss-writer-field
description: Kirby CMS versions prior to 4.9.4 and between 5.0.0-alpha.1 and 5.4.3 are vulnerable to a self-cross-site scripting (self-XSS) flaw, CVE-2026-49276, in the writer field, allowing an attacker to inject malicious JavaScript as the target of a link or email link which, if clicked by an authenticated user before saving, will execute in their browser context, potentially making API requests with their permissions, while Panel plugins using the `<k-writer>` component may be vulnerable to stored XSS if they don't sanitize HTML.
date: "2026-06-18T15:26:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - self-xss
  - web-vulnerability
  - kirby
  - cms
vendors:
  - Kirby
products:
  - composer/getkirby/cms <= 4.9.3
  - composer/getkirby/cms >= 5.0.0-alpha.1, <= 5.4.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1204
    technique_name: User Execution
references:
  - https://github.com/advisories/GHSA-rhj6-r49h-5932
rules:
  - title: Detects CVE-2026-49276 Exploitation — Kirby Panel JS URL Submission
    description: Detects attempts to submit 'javascript:' scheme URLs to Kirby CMS Panel endpoints, indicating potential CVE-2026-49276 exploitation attempt in the writer field.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
  - title: Detects Generic XSS Patterns in Kirby Panel Content Submissions
    description: Detects common XSS payload patterns (e.g., <script> tags, onerror attributes) in POST requests to Kirby CMS Panel endpoints, indicating attempts to inject malicious client-side code, potentially related to CVE-2026-49276 secondary effects.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The Kirby CMS is affected by a high-severity self-cross-site scripting (self-XSS) vulnerability, tracked as CVE-2026-49276, in its writer field. This flaw impacts Kirby sites using the writer field in any blueprint, specifically versions prior to 4.9.4 and versions 5.0.0-alpha.1 through 5.4.3. Attackers can inject malicious `javascript:` URLs into link or email targets within the writer field. While the backend sanitizes these before storage, an authenticated Panel user who enters such a malicious link and then clicks it *before saving the content* will execute the script in their browser. This can lead to the attacker making API requests with the victim's permissions. Successful exploitation typically requires social engineering and knowledge of the content structure, and cannot be automated. Panel plugins directly using the `<k-writer>` component may also be susceptible to stored XSS if they lack proper HTML sanitization.

## Attack Chain

1.  An attacker, with knowledge of the Kirby content structure, gains access to an authenticated Kirby Panel session (e.g., via stolen credentials or an insider threat).
2.  The attacker navigates to a content page utilizing the `writer` field within the Kirby Panel.
3.  The attacker crafts a malicious `javascript:` URL payload (e.g., `javascript:alert(document.domain)`) and inputs it into a "custom" link or email target within the `writer` field.
4.  The attacker then socially engineers or persuades another authenticated user (e.g., an administrator) to open the same content page in the Panel.
5.  The victim user clicks the maliciously crafted `javascript:` link that the attacker previously inserted into the `writer` field, but *before* saving the content changes.
6.  Upon clicking, the malicious JavaScript code embedded in the link executes within the victim's browser context, operating with the victim's Panel permissions.
7.  The script can then perform actions such as triggering API requests to Kirby's backend, exfiltrating sensitive session data, or escalating privileges by changing user settings.
8.  This leads to unauthorized actions being performed under the victim's identity within the Kirby CMS.

## Impact

This self-XSS vulnerability can lead to significant compromise of the Kirby CMS Panel. If an administrator account is targeted, successful exploitation allows the attacker to execute arbitrary JavaScript within the administrator's browser session. This can facilitate privilege escalation, unauthorized modification of content, data exfiltration from the Panel, or further actions through Kirby's API using the victim's permissions. While primarily self-XSS, Panel plugins using the vulnerable `<k-writer>` component could enable stored XSS, affecting other users or site visitors if not properly sanitized. The attack's effectiveness relies on social engineering, meaning the number of direct victims is hard to quantify but the potential for high impact on targeted individuals or organizations is severe.

## Recommendation

*   Patch CVE-2026-49276 immediately by updating Kirby CMS to version 4.9.4, 5.4.4, or a later release.
*   Deploy the Sigma rule "Detects CVE-2026-49276 Exploitation — Kirby Panel JS URL Submission" to your SIEM to identify attempts at submitting `javascript:` scheme URLs to your Kirby Panel.
*   Enable comprehensive web server logging, ensuring that full request bodies and URL parameters for POST requests to Kirby Panel endpoints (e.g., `/panel/api/pages/*/fields/writer`) are captured for forensic analysis and detection.
*   Educate users with Kirby Panel access, especially those with elevated privileges, about the risks of clicking untrusted links within the Panel interface, even if they appear to be self-generated.
