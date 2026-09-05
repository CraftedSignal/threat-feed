---
title: Stored Cross-Site Scripting in SureForms WordPress Plugin
slug: 2026-09-sureforms-xss
description: An unauthenticated Stored Cross-Site Scripting vulnerability in the SureForms WordPress plugin (up to 2.12.2) allows attackers to inject malicious scripts that execute in victim browsers.
date: "2026-09-05T07:30:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sureform:sureforms:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-18406
vendors:
  - SureForm
products:
  - SureForms – Contact Form Builder, AI Forms, Payment Form, Survey & Quiz (<= 2.12.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-18406
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18406
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update SureForms plugin to version 2.12.3 or later
      owner: IT Operations
      addresses: CVE-2026-18406
      evidence: Source states vulnerability exists in versions 2.12.2 and below.
---

The SureForms - Contact Form Builder, AI Forms, Payment Form, Survey & Quiz plugin for WordPress is susceptible to a Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-18406. This flaw exists in versions 2.12.2 and earlier. The vulnerability stems from the plugin's failure to adequately sanitize user-supplied input or perform proper output escaping within its text field functionality. 

An unauthenticated attacker can exploit this weakness by submitting malicious payloads via the plugin's text fields. Once injected, these scripts are stored on the server and executed within the context of the WordPress site whenever an administrator or another user views the compromised page. This provides an avenue for session hijacking, credential theft, or the unauthorized modification of site content. Defending against this requires immediate updates to the plugin, as the lack of input handling allows arbitrary JavaScript execution without prior authentication.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the browser of any user who views an affected page. This can lead to the compromise of user sessions, including those with administrative privileges, potentially resulting in full site takeover. The vulnerability affects all users of the SureForms plugin prior to version 2.12.3.

## Recommendation

Update the SureForms - Contact Form Builder, AI Forms, Payment Form, Survey & Quiz plugin to version 2.12.3 or the latest available release to mitigate CVE-2026-18406.
