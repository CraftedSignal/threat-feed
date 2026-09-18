---
title: CVE-2026-17086 PHP Object Injection in ShortPixel Image Optimizer
slug: 2026-09-shortpixel-php-injection
description: Authenticated attackers can exploit insecure deserialization in ShortPixel Image Optimizer versions 6.5.5 and below to execute arbitrary code if a POP chain is available via other plugins or themes.
date: "2026-09-18T06:03:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:shortpixel:shortpixel_image_optimizer:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - php-injection
  - deserialization
vendors:
  - ShortPixel
products:
  - ShortPixel Image Optimizer – Optimize Images, Convert WebP & AVIF (<= 6.5.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for authenticated attackers, with author-level access and above, to inject a PHP Object.
    confidence_band: high
cves:
  - id: CVE-2026-17086
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17086
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update ShortPixel Image Optimizer to a version greater than 6.5.5.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-17086 remediation guidance.
  mitigation_plan:
    - priority: medium_term
      action: Remove inactive or unnecessary plugins and themes from WordPress environments to reduce the surface area for POP chain discovery.
      owner: IT Operations
      addresses: CVE-2026-17086
      evidence: Source notes that the vulnerability relies on other plugins or themes containing a POP chain.
---

ShortPixel Image Optimizer for WordPress, version 6.5.5 and below, contains a PHP Object Injection vulnerability resulting from insecure deserialization of untrusted input. The flaw enables authenticated users with author-level access or higher to supply malicious serialized objects to the application. While the ShortPixel plugin does not inherently contain a Property Oriented Programming (POP) chain required to trigger exploitation, the vulnerability relies on the presence of secondary plugins or themes installed on the same WordPress instance that do contain a usable POP chain. If such a chain exists, an attacker could potentially achieve remote code execution, arbitrary file deletion, or sensitive data exfiltration. The severity of this issue is dependent on the overall plugin ecosystem of the host environment.

## Impact

Successful exploitation requires an authenticated attacker with at least author-level permissions and the presence of a separate vulnerable plugin or theme. Impact varies based on the discovered POP chain but may result in total site compromise, including unauthorized file system access or remote code execution. The scope of impact is limited to the WordPress environments where this specific combination of vulnerable plugin and secondary exploit chain exists.

## Recommendation

Update the ShortPixel Image Optimizer plugin to the latest available version beyond 6.5.5 to mitigate the deserialization vulnerability. Audit the WordPress environment to remove unused plugins and themes that may contain POP chains. Prioritize remediation based on the exposure of the administrative or author-level account interfaces and the overall plugin/theme attack surface.
