---
title: Stored Cross-Site Scripting Vulnerability in Strapi Content Manager
slug: 2026-09-strapi-xss
description: Strapi versions 4.x through 4.26.2 and 5.x before 5.48.1 are vulnerable to stored XSS via the WYSIWYG preview component, allowing an authenticated Author to trigger script execution in high-privilege sessions.
date: "2026-09-13T11:25:30Z"
lastmod: "2026-09-14T13:04:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:strapi:strapi:*:*:*:*:*:*:*:*
vendors:
  - Strapi
products:
  - Strapi (4.x <= 4.26.2, 5.x < 5.48.1)
  - Strapi (4.x-4.26.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An Author-role user can store malicious script tags in rich text fields that execute in an Editor or Super Admin's session.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.004
    technique_name: 'Server Software Component: Web Shell'
    evidence: An Author-role user can store malicious script tags in rich text fields that execute in an Editor or Super Admin's session.
    confidence_band: med
cves:
  - id: CVE-2026-90561
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90561
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3324
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Strapi to version 4.26.3 or 5.48.1
      owner: IT Operations
      addresses: CVE-2026-90561
      evidence: Strapi versions 4.x through 4.26.2 and 5.x before 5.48.1 contain a stored cross-site scripting vulnerability
updates:
  - at: "2026-09-14T13:04:08Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3324
---

Strapi versions 4.x through 4.26.2 and 5.x before 5.48.1 contain a stored cross-site scripting (XSS) vulnerability within the content manager's WYSIWYG preview component. The vulnerability exists because the application fails to adequately sanitize rich text fields, allowing for the injection of malicious script tags. An authenticated user possessing the 'Author' role can inject these scripts into content fields. When an 'Editor' or 'Super Admin' accesses the content and expands the preview pane, the malicious payload executes within their browser session. This flaw poses a significant risk for account takeover and unauthorized administrative access. Defenders should prioritize updating Strapi to the patched versions.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to execute arbitrary JavaScript in the context of high-privilege administrative sessions. This can lead to full account takeover of Editor or Super Admin accounts, unauthorized content manipulation, or the exfiltration of sensitive administrative data, significantly compromising the integrity and security of the Strapi content management environment.

## Recommendation

1. Upgrade all instances of Strapi to version 4.26.3 or 5.48.1 or later to remediate the sanitization failure associated with CVE-2026-90561.
2. Review user role assignments within the Strapi content manager to ensure that only trusted users are granted 'Author' privileges until patching is complete.
