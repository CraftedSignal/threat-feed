---
title: Umbraco Delivery API Authorization Bypass via Node Expansion
slug: 2026-09-umbraco-api-leak
description: Umbraco CMS contains an authorization bypass vulnerability (CVE-2026-69197) in the Delivery API where protected content is leaked when referenced by an unprotected node through expansion parameters.
date: "2026-09-17T19:14:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:umbraco:cms:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - api-security
  - umbraco
  - cve-2026-69197
vendors:
  - Umbraco
products:
  - Umbraco CMS (12.0.0-13.15.0, 14.0.0-17.5.2, 18.0.0-18.0.1)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1595
    technique_name: Active Scanning
    evidence: An anonymous / unauthorized caller can retrieve a protected node's Name, route, and id and Full property values when the request uses ?expand on the picker property.
    confidence_band: high
cves:
  - id: CVE-2026-69197
references:
  - https://github.com/advisories/GHSA-wr57-hqmp-fgvh
  - https://docs.umbraco.com/umbraco-cms/develop-with-umbraco/headless-and-apis/content-delivery-api
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69197
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Umbraco CMS to patched versions 13.15.1, 17.5.3, or 18.0.2
      owner: IT Operations
      due: 48h
      evidence: Source Patches section
  mitigation_plan:
    - priority: immediate
      action: Restrict public access to Delivery API endpoints if upgrade is delayed
      owner: IT Operations
      addresses: CVE-2026-69197
      evidence: Source Impact section
---

Umbraco CMS contains a critical authorization bypass vulnerability, tracked as CVE-2026-69197, affecting the Content Delivery API. The vulnerability stems from a flaw in the controller-layer access validation, which only enforces member-gated (Public Access) protections when a protected node is requested directly. When a publicly accessible (unprotected) node references a protected node via a Content Picker, Multi-Node Tree Picker, or nested block structures, the Delivery API fails to propagate access checks during expansion.

An unauthenticated attacker can supply the '?expand' query parameter in a request for a public node to force the API to serialize and disclose the full property values of linked protected content. While a direct request to the protected node correctly returns a 401 Unauthorized status, the expansion mechanism exposes the internal properties, routes, and identifiers of member-gated data. This affects Umbraco CMS versions 12.0.0 through 13.15.0, 14.0.0 through 17.5.2, and 18.0.0 through 18.0.1.

## Impact

Successful exploitation allows unauthorized retrieval of sensitive, member-gated information such as pricing structures, internal documentation, and restricted articles. The impact is highest when the Delivery API is configured for public access, though it remains exploitable in environments gated by API keys if the attacker possesses legitimate access to a public node that references protected content.

## Recommendation

Prioritized, concrete actions for security operations and IT teams:
- Upgrade Umbraco CMS to version 13.15.1, 17.5.3, or 18.0.2 to address CVE-2026-69197.
- Audit Delivery API logs for high-frequency use of the '?expand' query parameter across public nodes to identify potential enumeration or data exfiltration attempts.
- Review Content Picker configurations to identify nodes that reference sensitive, member-gated content, and restrict API access to these paths until patching is complete.
