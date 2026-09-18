---
title: SSRF Vulnerability in Obot via Remote MCP Server URLs
slug: 2026-09-obot-ssrf
description: Obot versions 0.22.1 and earlier are vulnerable to server-side request forgery (SSRF) allowing authenticated privileged users to probe internal network resources and cloud instance metadata services.
date: "2026-09-18T19:48:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cloud-security
  - vulnerability
vendors:
  - Obot
products:
  - Obot (<= 0.22.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The URL of a remote MCP server is attacker-controlled at registration and is fetched server-side with no validation of the destination.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials In Files'
    evidence: Against 169.254.169.254 this can disclose the host's cloud IAM credentials, enabling a pivot into the cloud account.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-jgh3-fggc-mcpm
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Obot instances to version 0.23.0 or later.
      owner: IT Operations
      due: 48h
      evidence: Mitigation section recommends upgrade to v0.23.0 or later.
  mitigation_plan:
    - priority: immediate
      action: Patch Obot to v0.23.0 to enable mandatory egress filtering.
      owner: IT Operations
      addresses: SSRF vulnerability via MCP server URL
      evidence: The patch applies a single outbound egress chokepoint rejecting loopback, link-local, and RFC1918 ranges.
---

Obot versions 0.22.1 and earlier contain a server-side request forgery (SSRF) vulnerability that allows authenticated users with the Power User, Power User Plus, or Admin role to coerce the application into making unauthorized outbound HTTP requests. During the registration of a remote Model Context Protocol (MCP) server, the application accepts a user-provided URL without adequate validation of the destination. 

The application performs server-side fetches to this URL during runtime initialization and automatic OAuth discovery metadata synchronization. Because the application fails to enforce egress filtering against internal subnets (RFC1918), link-local addresses, or the cloud instance metadata service (169.254.169.254), an attacker can access sensitive internal endpoints. Furthermore, since the application reflects response bodies in its error messages, this vulnerability facilitates non-blind exfiltration of data, including cloud IAM credentials, which could lead to broader account compromise. The existing 'DisallowLocalhostMCP' configuration is disabled by default and insufficient to mitigate these risks.

## Impact

Successful exploitation allows an attacker with sufficient privileges to bypass network segmentation to probe internal services inaccessible from the public internet. Access to the cloud instance metadata service (169.254.169.254) can lead to the exposure of host IAM credentials, potentially resulting in full cloud account compromise. This vulnerability carries a CVSS v3.1 score of 7.6.

## Recommendation

Upgrade Obot to version 0.23.0 or later immediately. The patch introduces a unified egress filtering mechanism that proactively blocks access to loopback, link-local, RFC1918, and IPv6 ULA addresses at the dial time for both the MCP client and the OAuth metadata client. Ensure that the 'DisallowLocalhostMCP' configuration, if applicable in existing environments prior to upgrading, is strictly monitored for misconfiguration.
