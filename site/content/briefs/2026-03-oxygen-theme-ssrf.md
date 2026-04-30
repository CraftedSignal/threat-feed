---
title: Oxygen Theme WordPress Plugin Vulnerable to Server-Side Request Forgery (CVE-2025-12886)
slug: 2026-03-oxygen-theme-ssrf
description: The Oxygen Theme for WordPress is vulnerable to Server-Side Request Forgery (SSRF) in versions up to 6.0.8, allowing unauthenticated attackers to make arbitrary web requests via the laborator_calc_route AJAX action.
date: "2026-03-28T04:16:49Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - ssrf
  - wordpress
  - oxygen-theme
  - cve-2025-12886
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-12886
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/8c83f430-8a4d-40fa-890c-387c787a3b55?source=cve
rules:
  - title: Oxygen Theme SSRF Detection
    description: Detects potential SSRF attempts via the laborator_calc_route AJAX action in the Oxygen Theme for WordPress.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Oxygen Theme SSRF Detection - Internal IP Address
    description: Detects potential SSRF attempts to access internal IP addresses via the laborator_calc_route AJAX action in the Oxygen Theme for WordPress.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Oxygen Theme WordPress plugin, versions 6.0.8 and earlier, contains a Server-Side Request Forgery (SSRF) vulnerability (CVE-2025-12886). This flaw allows unauthenticated attackers to send crafted requests to the WordPress server, potentially forcing it to make outbound connections to internal or external resources. The vulnerability is located within the `laborator_calc_route` AJAX action. By exploiting this, attackers can potentially access sensitive internal resources, bypass firewall…
