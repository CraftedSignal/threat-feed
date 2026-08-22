---
title: PHP Object Injection in WS Form LITE
slug: 2026-08-ws-form-injection
description: The WS Form LITE plugin for WordPress is vulnerable to unauthenticated PHP Object Injection via unsanitized form submission meta values, potentially leading to RCE or data exfiltration if combined with a secondary POP chain.
date: "2026-08-22T17:31:56Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WS Form
products:
  - WS Form LITE (<= 1.10.80)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The WS Form LITE plugin for WordPress is vulnerable to PHP Object Injection ... This makes it possible for unauthenticated attackers to inject a PHP Object.
    confidence_band: high
cves:
  - id: CVE-2026-4703
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4703
---

The WS Form LITE plugin for WordPress, specifically versions 1.10.80 and earlier, contains a critical PHP Object Injection vulnerability (CVE-2026-4703). The issue stems from the unsafe deserialization of untrusted user input within form submission meta values. While the plugin does not ship with a native Property-Oriented Programming (POP) chain, attackers can leverage this deserialization primitive to trigger arbitrary file deletion, data exfiltration, or remote code execution (RCE) if other installed plugins or themes provide the necessary gadgets. Because this can be triggered by unauthenticated users, the attack surface includes any WordPress instance using the affected version of the plugin, provided the hosting environment contains vulnerable gadgets in the broader plugin ecosystem.

## Impact

Successful exploitation requires a secondary POP chain to be present on the target WordPress site. If such a chain exists, the impact includes full site compromise, unauthorized data access, and persistent code execution, depending on the capabilities of the available gadgets. The severity is high due to the potential for unauthenticated access to the deserialization routine.

## Recommendation

Update the WS Form LITE plugin to the latest version immediately to remediate the unsafe deserialization entry point. Detection teams should audit WordPress environments for the presence of the vulnerable plugin version using vulnerability management tools. Monitor server access logs for unusual POST requests directed at form submission endpoints that deviate from expected patterns, particularly those containing serialized PHP data structures. Ensure all installed plugins and themes are audited to identify and remove any components that contain dangerous POP chain gadgets.
