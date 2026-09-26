---
title: Authentication Bypass in Grav CMS Comments Plugin
slug: 2026-09-grav-comments-vuln
description: An authentication bypass vulnerability in the Grav CMS Comments plugin through version 1.2.10 allows unauthenticated attackers to exfiltrate comment data, including emails and server paths, via an improperly secured admin handler.
date: "2026-09-26T15:10:05Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:grav:cms_comments_plugin:*:*:*:*:*:*:*:*
tags:
  - cms
  - authentication-bypass
  - webserver
  - information-disclosure
vendors:
  - Grav
products:
  - Grav CMS Comments plugin (<= 1.2.10)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: An unauthenticated remote attacker can request /admin/comments/page:<n> and retrieve every comment from the last 7 days, including ... the absolute server filesystem path.
    confidence_band: high
cves:
  - id: CVE-2026-100672
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100672
rules:
  - title: Detects CVE-2026-100672 Exploitation - Unauthenticated Comment Data Retrieval
    description: Detects attempts to access the Comments plugin admin API endpoint which is vulnerable to unauthenticated data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Grav CMS Comments plugin to 1.2.11
      owner: IT Operations
      due: 48h
      evidence: Source states issue is fixed in 1.2.11
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /admin/comments/ at the webserver level
      owner: IT Operations
      addresses: CVE-2026-100672
      evidence: Vulnerability allows unauthenticated access to this path
---

The Comments plugin for Grav CMS (getgrav/grav-plugin-comments) through version 1.2.10 contains a critical authentication bypass vulnerability (CVE-2026-100672). The plugin registers an admin handler that fails to verify the authentication state of the requester, relying instead on an incorrect check (isAdmin()) that only validates the presence of the admin service on the requested route. This flaw allows an unauthenticated remote attacker to query the /admin/comments/page: endpoints. Because this handler executes during the plugin stage before the Admin plugin initiates its standard login procedures, attackers can bypass authentication entirely. Successful exploitation results in the unauthorized disclosure of sensitive comment metadata, including commenter email addresses and absolute server filesystem paths, which can facilitate further reconnaissance against the hosting environment. This issue does not affect the Grav 2.0 Admin Next stack.

## Impact

The vulnerability leads to the unauthorized exfiltration of site comment data, exposing PII such as email addresses and revealing internal server directory structures. This information leak aids attackers in conducting targeted phishing or mapping the backend filesystem to identify further attack surfaces.

## Recommendation

* Upgrade the Grav CMS Comments plugin to version 1.2.11 or later to remediate CVE-2026-100672.
* Audit logs for suspicious GET requests to the /admin/comments/ path from unauthenticated sources or anomalous IPs.
* Restrict access to the /admin/ directory at the web server level (e.g., using Nginx or Apache allowlisting) if the update cannot be applied immediately.
