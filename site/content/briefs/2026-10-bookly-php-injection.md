---
title: PHP Object Injection Vulnerability in Bookly WordPress Plugin
slug: 2026-10-bookly-php-injection
description: The Bookly plugin for WordPress contains a PHP Object Injection vulnerability in versions 28.2 and earlier, allowing authenticated users with custom-level access to inject arbitrary PHP objects.
date: "2026-10-10T07:52:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:bookly:*:*:*:*:*:*:*:*
tags:
  - web-application
  - php-injection
  - wordpress
  - cve-2026-12626
vendors:
  - WordPress
products:
  - Bookly (<= 28.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Bookly plugin for WordPress is vulnerable to PHP Object Injection via deserialization of untrusted input.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: This makes it possible for authenticated attackers, with custom-level access and above, to inject a PHP Object.
    confidence_band: high
cves:
  - id: CVE-2026-12626
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12626
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Bookly plugin to the latest version to patch CVE-2026-12626
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-12626 advisory
  enrichment_needed:
    - item: Identify active exploit chains for CVE-2026-12626
      owner: CTI
      reason: Assess risk level based on availability of weaponized payloads
      evidence: NVD report
  mitigation_plan:
    - priority: immediate
      action: Review and audit user accounts with custom-level access or higher
      owner: Security Operations
      addresses: CVE-2026-12626
      evidence: Plugin requires custom-level access to exploit
---

The Bookly plugin for WordPress is affected by a PHP Object Injection vulnerability tracked as CVE-2026-12626. The issue stems from insecure deserialization of untrusted input provided through the 'value' parameter within the plugin. An attacker must possess at least custom-level access to the WordPress application to exploit this flaw. By injecting a malicious serialized PHP object, an attacker could potentially achieve remote code execution (RCE) if specific gadget chains are present within the target environment's codebase. As of this report, there is no known functional gadget chain, but the ability to inject arbitrary objects represents a significant security risk for WordPress installations utilizing this plugin for appointment scheduling. Organizations should prioritize updating the plugin to the latest version.

## Impact

Successful exploitation allows authenticated attackers with elevated privileges to execute arbitrary code within the context of the web server. This could lead to full site compromise, data exfiltration of appointment and customer records, or lateral movement into the hosting infrastructure.

## Recommendation

- Update the Bookly WordPress plugin to the version released following 28.2 to mitigate CVE-2026-12626.
- Review WordPress user roles and capabilities to ensure that custom-level access or higher is restricted to trusted, verified administrators.
- Audit server-side application logs for suspicious HTTP POST requests containing serialized PHP data structures targeted at the Bookly plugin endpoints.
