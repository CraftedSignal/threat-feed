---
title: Information Disclosure Vulnerability in OpenAgents Workspace
slug: 2026-10-openagents-info-disclosure
description: An information disclosure vulnerability in the OpenAgents Workspace backend allows unauthenticated attackers to exfiltrate workspace metadata and API keys via the /v1/workspaces endpoint.
date: "2026-10-11T14:01:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openagents:workspace:*:*:*:*:*:*:*:*
tags:
  - information-disclosure
  - api-security
  - cloud
vendors:
  - OpenAgents
products:
  - Workspace (<= launcher-v1.0.17)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: This flaw allows unauthenticated remote attackers to retrieve sensitive workspace metadata, including workspace identifiers, slugs, member lists, and creator email addresses.
    confidence_band: high
cves:
  - id: CVE-2026-108739
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108739
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade OpenAgents Workspace to the latest version to remediate CVE-2026-108739.
      owner: IT Operations
      due: 48h
      evidence: Source confirms vulnerability in versions through launcher-v1.0.17.
  mitigation_plan:
    - priority: immediate
      action: Restrict unauthenticated access to the /v1/workspaces endpoint via WAF.
      owner: Security Engineering
      addresses: CVE-2026-108739
      evidence: Vulnerability allows unauthenticated access to sensitive metadata via this specific API path.
---

The OpenAgents Workspace backend, specifically versions through launcher-v1.0.17, contains a critical information disclosure vulnerability. This flaw resides in the /v1/workspaces API endpoint, which fails to properly authenticate requests. An unauthenticated remote attacker can issue a GET request to this endpoint to retrieve a comprehensive list of all workspaces within an organization's deployment. The response includes sensitive information such as internal workspace identifiers, URL slugs, lists of member email addresses, and the unmasked 'browserfabric_api_key'. Access to these API keys poses a significant risk of further exploitation, as they may be used to access external services or manipulate the underlying browser infrastructure associated with those workspaces. This vulnerability was identified as CVE-2026-108739.

## Impact

Successful exploitation allows for the unauthorized mass exfiltration of organizational structure, internal user email addresses, and active API credentials. Exposure of the 'browserfabric_api_key' effectively grants an attacker the ability to hijack existing browser sessions or interact with the platform as an authenticated user, potentially leading to data theft or further unauthorized access to integrated systems.

## Recommendation

Prioritize immediate patching of the OpenAgents Workspace backend. Upgrade all instances running version 1.0.17 or earlier to the latest secure version released by the vendor that addresses CVE-2026-108739. If immediate patching is not possible, implement a temporary restriction on external access to the /v1/workspaces API endpoint at the reverse proxy or WAF layer for all unauthenticated traffic.
