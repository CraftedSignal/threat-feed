---
title: Smarty Template Inheritance Code Injection Vulnerability
slug: 2026-10-smarty-rce
description: Smarty versions before 4.5.8 and 5.8.5 are susceptible to code injection via template inheritance due to improper management of the nocache_hash variable, enabling unauthenticated remote code execution.
date: "2026-10-06T14:55:49Z"
lastmod: "2026-10-07T06:38:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:smarty:smarty:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=0D71BB83-F55B-5D6D-B9DD-846D59C52489&utm_source=rss&utm_medium=rss
tags:
  - remote-code-execution
  - vulnerability
  - php
vendors:
  - Smarty
products:
  - Smarty (< 4.5.8, 5.x < 5.8.5)
  - Smarty (< 4.5.8)
  - Smarty (5.0.0 – 5.8.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows an attacker to supply assigned data containing a forged SmartyNocache marker that is copied verbatim into the regenerated PHP cache file, executing arbitrary PHP on include for remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-82531
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82531
  - https://sploitus.com/exploit?id=0D71BB83-F55B-5D6D-B9DD-846D59C52489&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Smarty to 4.5.8 or 5.8.5
      owner: IT Operations
      due: 48h
      evidence: Source states Smarty before 4.5.8 and 5.x before 5.8.5 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Smarty 4.5.8 or 5.8.5
      owner: IT Operations
      addresses: CVE-2026-82531
      evidence: NVD vulnerability details
updates:
  - at: "2026-10-07T06:38:00Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=0D71BB83-F55B-5D6D-B9DD-846D59C52489&utm_source=rss&utm_medium=rss
---

Smarty versions 4.x before 4.5.8 and 5.x before 5.8.5 contain a critical code injection vulnerability caused by the improper restoration of the top-level nocache_hash during template inheritance processing. When using the extends:/multi-component template inheritance feature, the hash value is left as null. An attacker can supply crafted input containing a forged SmartyNocache marker as assigned data to the template engine. Because the engine fails to properly sanitize or scope this data during the cache regeneration process, the forged marker is written verbatim into the compiled PHP cache file. Subsequent requests that trigger the inclusion of this cached file cause the injected PHP payload to be executed on the server, resulting in arbitrary remote code execution (RCE). This vulnerability is particularly dangerous in web applications that allow user-controllable input to influence template variables.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary PHP code on the underlying web server. This can lead to full application compromise, data exfiltration, or the establishment of persistent backdoors within the web environment. The vulnerability impacts any application utilizing the affected Smarty template inheritance mechanism and exposed via user-supplied template data.

## Recommendation

Prioritize the immediate remediation of vulnerable Smarty installations by upgrading to the patched versions.

- Upgrade Smarty 4.x installations to version 4.5.8 or later.
- Upgrade Smarty 5.x installations to version 5.8.5 or later.
- Audit existing Smarty template implementations to ensure that user-supplied data is strictly sanitized before being assigned to templates, limiting the attacker's ability to inject payloads into the template engine.
- Monitor web server error and access logs for unusual PHP execution patterns originating from cached template files or unexpected write operations to the template cache directory.
