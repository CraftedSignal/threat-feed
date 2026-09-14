---
title: Multiple Vulnerabilities in Squid Proxy
slug: 2026-09-squid-vulnerabilities
description: Multiple security vulnerabilities identified in Squid versions prior to 7.7 allow remote attackers to cause denial-of-service, manipulate data, and bypass security policy restrictions.
date: "2026-09-14T19:03:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - proxy
  - squid
  - cve-2026-61642
vendors:
  - Squid
products:
  - Squid (< 7.7)
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1168/
  - https://github.com/squid-cache/squid/security/advisories/GHSA-537g-4gfh-w7m6
  - https://github.com/squid-cache/squid/security/advisories/GHSA-j9pf-q9f6-v44c
  - https://github.com/squid-cache/squid/security/advisories/GHSA-vh99-xw7j-fx5c
  - https://www.cve.org/CVERecord?id=CVE-2026-61642
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all Squid installations to 7.7 or later
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends updating to version 7.7 or later
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 7.7
      owner: IT Operations
      addresses: CVE-2026-61642
      evidence: Source advisory cites version 7.7 as the fixed release
---

The French National Cybersecurity Agency (ANSSI) has released an advisory regarding multiple critical vulnerabilities affecting the Squid web proxy cache, specifically impacting all versions prior to 7.7. These vulnerabilities pose significant risks, including remote denial-of-service (DoS) attacks, unauthorized manipulation of cached data, and the circumvention of established security policies. The issues were documented via several GitHub Security Advisories (GHSA-537g-4gfh-w7m6, GHSA-j9pf-q9f6-v44c, and GHSA-vh99-xw7j-fx5c) and are tracked under CVE-2026-61642. Given the role of Squid as a central gateway for enterprise web traffic, exploitation of these flaws could allow an attacker to disrupt organizational connectivity or intercept and modify proxied traffic. Organizations currently running versions of Squid older than 7.7 should prioritize testing and deployment of the patches provided by the maintainers.

## Impact

Successful exploitation of these vulnerabilities can lead to service outages impacting all users routing through the affected proxy, as well as the loss of data integrity for cached resources. By bypassing security policies, an attacker may be able to reach internal restricted resources or exfiltrate data by evading access control lists (ACLs) enforced at the proxy level. Given the widespread deployment of Squid in enterprise environments, the potential for broad disruption is substantial.

## Recommendation

- Upgrade all instances of Squid proxy to version 7.7 or later immediately to resolve the vulnerabilities referenced in GHSA-537g-4gfh-w7m6, GHSA-j9pf-q9f6-v44c, and GHSA-vh99-xw7j-fx5c.
- Review Squid access logs and error logs for anomalous spikes in request failure rates or unexpected response codes (e.g., frequent 5xx errors) that may indicate exploitation attempts targeting DoS vulnerabilities.
- Implement network-level access controls to restrict management access to the proxy server to authorized administrative IP addresses only.
