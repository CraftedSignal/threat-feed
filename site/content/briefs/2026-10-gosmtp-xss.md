---
title: Stored XSS Vulnerability in GoSMTP Pro for WordPress
slug: 2026-10-gosmtp-xss
description: An unauthenticated stored XSS vulnerability in GoSMTP Pro (<= 1.2.3) allows attackers to inject arbitrary web scripts via email log body content.
date: "2026-10-16T10:26:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gosmtp:gosmtp_pro:*:*:*:*:*:wordpress:*:*
vendors:
  - GoSMTP
products:
  - GoSMTP Pro (<= 1.2.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96768
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96768
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable GoSMTP Pro plugin on all WordPress instances
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-96768 CVSS 7.2
  mitigation_plan:
    - priority: immediate
      action: Upgrade or remove GoSMTP Pro to remediate CVE-2026-96768
      owner: IT Operations
      addresses: CVE-2026-96768
      evidence: NVD vulnerability disclosure
---

The GoSMTP Pro plugin for WordPress is affected by a stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-96768, which affects all versions up to and including 1.2.3. The flaw exists due to insufficient input sanitization and output escaping when processing email log body content. An unauthenticated attacker can exploit this by crafting a malicious payload that bypasses WordPress's standard moderation filters, as the plugin incorrectly handles entity-encoded tag delimiters. 

When the payload is processed, it is written verbatim into the plugin's email log database table. The malicious script executes in the browser of any user - typically an administrator - who views the email log via the WordPress dashboard. Because the payload passes initial moderation checks as safe text before being decoded, this vulnerability presents a significant risk for session hijacking or unauthorized administrative actions. Defenders should prioritize patching or disabling the plugin until an update is applied.

## Impact

The vulnerability enables unauthenticated attackers to execute arbitrary JavaScript in the context of an authenticated user's session. If successful, this can lead to full account takeover of administrative accounts, unauthorized configuration changes, or the injection of additional malicious content within the WordPress environment. This vulnerability affects all installations of GoSMTP Pro version 1.2.3 and below.

## Recommendation

* Immediately disable the GoSMTP Pro plugin until a patch is available or upgrade to a version remediating CVE-2026-96768.
* Audit WordPress administrative dashboard access logs for suspicious activity targeting email log views.
* Implement or strengthen Content Security Policy (CSP) headers to restrict the execution of unauthorized scripts in the WordPress dashboard.
