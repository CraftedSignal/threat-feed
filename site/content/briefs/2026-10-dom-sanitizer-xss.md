---
title: Incomplete Blacklist Vulnerability in rhukster dom-sanitizer
slug: 2026-10-dom-sanitizer-xss
description: The SVG Sanitization component in rhukster dom-sanitizer versions 1.0.15 and earlier contains an incomplete blacklist vulnerability in src/DOMSanitizer.php, allowing remote attackers to bypass security filters via malicious URL inputs.
date: "2026-10-01T16:12:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rhukster:dom-sanitizer:*:*:*:*:*:*:*:*
vendors:
  - rhukster
products:
  - dom-sanitizer (<= 1.0.15)
cves:
  - id: CVE-2026-103687
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103687
action_plan:
  priority: elevated
  owners:
    - Development
    - Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade rhukster dom-sanitizer to version 1.0.16.
      owner: Development
      addresses: CVE-2026-103687
      evidence: Upgrading to version 1.0.16 is sufficient to fix this issue.
---

A security vulnerability identified as CVE-2026-103687 exists within the rhukster dom-sanitizer library, specifically affecting versions up to and including 1.0.15. The issue is located in the SVG Sanitization component, within the `url` function of `src/DOMSanitizer.php`. The vulnerability stems from an incomplete blacklist implementation, which allows remote attackers to supply specially crafted input that evades existing sanitization logic. This flaw can lead to cross-site scripting (XSS) or other injection-based attacks if the library is used to process untrusted user content. Exploitation can be performed remotely by submitting malicious payloads to applications utilizing the affected library. The maintainers have released a fix in version 1.0.16.

## Impact

Successful exploitation of this vulnerability allows remote attackers to bypass sanitization filters, potentially leading to unauthorized script execution in the context of the user's browser. This could be used to facilitate session hijacking, data theft, or other malicious actions within web applications relying on this library for SVG sanitization.

## Recommendation

Prioritized actions for development and security teams:
- Upgrade the rhukster dom-sanitizer library to version 1.0.16 or later to address CVE-2026-103687.
- Review applications utilizing the library to ensure input processed by the SVG Sanitization component is validated against an updated security policy.
- Perform code reviews on implementations using the `url` function within `src/DOMSanitizer.php` to identify any existing payloads leveraging the incomplete blacklist.
