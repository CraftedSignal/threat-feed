---
title: Proxy-addr IP Spoofing via Misconfigured IPv4-mapped IPv6 Subnets
slug: 2026-10-proxy-addr-spoofing
description: The proxy-addr package is vulnerable to IP spoofing due to improper validation of IPv4-mapped IPv6 trust subnets, allowing attackers to manipulate X-Forwarded-For headers and bypass IP-based security controls.
date: "2026-10-06T12:45:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:proxy-addr_project:proxy-addr:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - web-application
  - network-security
products:
  - proxy-addr (< 2.0.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This allows unauthenticated attackers to manipulate the X-Forwarded-For header, effectively bypassing IP-based access controls, rate limiting, and audit logging mechanisms.
    confidence_band: high
cves:
  - id: CVE-2026-90711
    cvss: 9.1
    epss: 0.00332
references:
  - https://github.com/advisories/GHSA-jqcg-44mw-7w3h
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade proxy-addr to 2.0.8 across all node.js deployments
      owner: IT Operations
      due: 24h
      evidence: Upgrade to proxy-addr 2.0.8.
  mitigation_plan:
    - priority: immediate
      action: Review trust subnet configurations for IPv4-mapped IPv6 patterns
      owner: IT Operations
      addresses: CVE-2026-90711
      evidence: Write IPv4 trust subnets in plain IPv4 notation.
---

The proxy-addr package (versions 1.1.0 through 2.0.7) contains a vulnerability that leads to IP spoofing when applications use specific IPv4-mapped IPv6 trust subnets. When an application configures a trust subnet using an IPv4-mapped IPv6 address with a short prefix, such as ::ffff:10.0.0.0/8 (intended to be ::ffff:10.0.0.0/104), the library incorrectly compiles the subnet as matching all IPv4 addresses rather than the specified block. This misconfiguration causes the application to treat every incoming client as a trusted proxy.

Consequently, applications relying on proxy-addr (commonly used by Express) will accept the X-Forwarded-For header provided by any unauthenticated client as the legitimate remote IP address. This flaw allows attackers to bypass IP-based access controls, rate limiting, and geolocation restrictions, while simultaneously poisoning audit logs with attacker-controlled IP addresses. The vulnerability affects any configuration where an IPv6 trust subnet includes zero leading bits, such as ::/1.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass security measures dependent on the client IP address. This impacts any application using Express or other frameworks that leverage proxy-addr for IP trust decisions. If exploited, an attacker can bypass rate limiting, circumvent IP-based authentication, and mislead security monitoring systems by injecting arbitrary values into the X-Forwarded-For header. The scope is widespread for web applications that utilize complex IPv6/IPv4-mapped networking configurations.

## Recommendation

- Upgrade the proxy-addr package to version 2.0.8 or later immediately to patch CVE-2026-90711.
- Audit existing proxy-addr trust configurations for IPv4-mapped IPv6 notation.
- If IPv4-mapped notation is required, ensure the prefix covers the full mapped marker (e.g., use ::ffff:10.0.0.0/104 instead of /8).
- Prefer plain IPv4 notation (e.g., 10.0.0.0/8) for IPv4 subnets to eliminate potential parsing ambiguity.
