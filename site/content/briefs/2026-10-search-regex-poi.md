---
title: 'CVE-2026-104932: PHP Object Injection in Search Regex WordPress Plugin'
slug: 2026-10-search-regex-poi
description: The Search Regex WordPress plugin version 3.5 is vulnerable to PHP Object Injection, allowing authenticated users with subscriber access to achieve remote code execution via a POP chain.
date: "2026-10-16T08:25:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:search_regex_project:search_regex:3.5:*:*:*:*:wordpress:*:*
tags:
  - web-vulnerability
  - wordpress
  - php-injection
vendors:
  - WordPress
products:
  - Search Regex (3.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505.002
    technique_name: Server Software Component
    evidence: The Search Regex plugin for WordPress is vulnerable to PHP Object Injection in version 3.5 via deserialization of untrusted input in the replace_all function.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The additional presence of a POP chain allows attackers to execute code.
    confidence_band: high
cves:
  - id: CVE-2026-104932
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104932
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Search Regex plugin to a version patched for CVE-2026-104932
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Disable Search Regex plugin if no update is available
      owner: IT Operations
      addresses: CVE-2026-104932
      evidence: NVD vulnerability disclosure
---

CVE-2026-104932 is a critical security vulnerability found in the Search Regex plugin for WordPress, specifically affecting version 3.5. The vulnerability resides within the 'replace_all' function, which performs insecure deserialization of untrusted input provided by a user. Because the plugin does not adequately validate or sanitize the data before deserializing it, an authenticated attacker with at least subscriber-level permissions can inject a malicious PHP object. The presence of a property-oriented programming (POP) chain within the application context enables the attacker to leverage this injection to execute arbitrary code on the underlying server. Given that subscriber-level accounts are often easily obtainable via registration or compromise, this vulnerability presents a significant risk for privilege escalation and full site compromise.

## Impact

Successful exploitation of CVE-2026-104932 results in remote code execution (RCE) on the WordPress server. This allows attackers to gain full control over the compromised site, potentially leading to data exfiltration, the deployment of backdoors, or lateral movement into the hosting infrastructure. The vulnerability affects all WordPress installations utilizing version 3.5 of the Search Regex plugin.

## Recommendation

Prioritize the immediate update of the Search Regex plugin. If an update addressing this vulnerability is not available, disable the plugin until a patch is applied.

- Update the Search Regex plugin to the latest version that remediates CVE-2026-104932 immediately.
- Review web server logs for suspicious POST requests targeting the Search Regex plugin functionality, specifically monitoring for unusual serialized data strings in application parameters.
- Audit user accounts to identify and disable unauthorized or suspicious subscriber-level accounts that could be used as an initial access vector for this vulnerability.
