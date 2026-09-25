---
title: CVE-2026-100390 - IP Spoofing Vulnerability in Zoraxy
slug: 2026-09-zoraxy-ipv6-spoofing
description: Zoraxy versions 3.2.3 through 3.3.4 contain a vulnerability in IPv6 address parsing that allows unauthenticated attackers to spoof the X-Forwarded-For header and bypass IP-based access controls.
date: "2026-09-25T22:55:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zoraxy:zoraxy:3.2.3:*:*:*:*:*:*:*
  - cpe:2.3:a:zoraxy:zoraxy:3.3.4:*:*:*:*:*:*:*
tags:
  - vulnerability
  - webserver
  - network-security
vendors:
  - Zoraxy
products:
  - Zoraxy (3.2.3 - 3.3.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers connecting over IPv6 can supply arbitrary X-Forwarded-For values to spoof their source IP and bypass authorization provider IP-based access controls.
    confidence_band: high
cves:
  - id: CVE-2026-100390
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100390
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Zoraxy to a version newer than 3.3.4
      owner: IT Operations
      addresses: CVE-2026-100390
      evidence: Source advisory recommends addressing the vulnerability in the software.
---

Zoraxy versions 3.2.3 through 3.3.4 are affected by a vulnerability in how the RemoteAddr field processes IPv6 addresses when setting forwarded headers. An unauthenticated attacker can exploit this flaw by initiating a request over an IPv6 connection. Due to improper parsing of the source address, the application can be forced to accept an arbitrary value provided in the X-Forwarded-For header as the legitimate source IP. This vulnerability is significant for organizations that rely on IP-based allowlisting or access control lists (ACLs) within the Zoraxy reverse proxy or the services it protects. By spoofing a trusted internal or management IP, an attacker may gain unauthorized access to restricted application endpoints or bypass secondary authentication measures that rely on network location.

## Impact

The vulnerability allows for the bypass of IP-based security controls, potentially granting unauthenticated access to sensitive administrative interfaces or internal services protected by the reverse proxy. Attackers can leverage this to gain unauthorized entry to backend systems that trust the X-Forwarded-For header provided by the proxy.

## Recommendation

Update Zoraxy to a version newer than 3.3.4 to remediate CVE-2026-100390. If immediate patching is not feasible, restrict external IPv6 access to the Zoraxy management interfaces or application endpoints that utilize IP-based filtering.
