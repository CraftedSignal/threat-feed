---
title: Authentication Bypass in NullHub Management API
slug: 2026-10-nullhub-auth-bypass
description: NullHub versions through 2026.5.29 contain a missing authentication vulnerability allowing unauthenticated remote access to management API endpoints.
date: "2026-10-14T16:36:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nullhub:nullhub:*:*:*:*:*:*:*:*
vendors:
  - NullHub
products:
  - NullHub (<= 2026.5.29)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: NullHub through 2026.5.29 contains a missing authentication vulnerability that allows unauthenticated attackers to access the /api/* management API.
    confidence_band: high
cves:
  - id: CVE-2026-110616
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110616
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Restrict NullHub management API access to local loopback interfaces
      owner: IT Operations
      due: 24h
      evidence: Source notes that non-loopback listeners are susceptible to remote exploitation
  mitigation_plan:
    - priority: immediate
      action: Upgrade NullHub to a version newer than 2026.5.29
      owner: IT Operations
      addresses: CVE-2026-110616
      evidence: NVD advisory for CVE-2026-110616
---

NullHub versions 2026.5.29 and earlier are affected by an authentication bypass vulnerability (CVE-2026-110616). The flaw stems from an improperly initialized 'auth_token' field within the application's management API (/api/*), which defaults to null and remains unassigned during operation. This allows unauthenticated attackers to interact with the management interface by sending HTTP requests that lack 'Authorization' or 'Origin' headers. 

When the service is configured to listen on non-loopback interfaces, an attacker can gain unauthorized control over agent instances. Successful exploitation enables an attacker to rewrite configuration files, extract sensitive provider credentials, manage cron jobs, and manipulate MCP (Model Context Protocol) servers. Given the critical nature of these functions, this vulnerability allows for complete compromise of the affected NullHub instance and potential lateral movement into integrated systems. Organizations should restrict management API access to loopback interfaces as an immediate mitigation until patching is performed.

## Impact

Successful exploitation results in full unauthorized control over NullHub agent instances. Attackers can exfiltrate provider credentials, establish persistence via modified cron jobs, and execute arbitrary commands through malicious MCP server configurations. This impacts any organization using NullHub for automation or agent management, particularly those exposing the management API to wider network segments.

## Recommendation

* Patch NullHub to a version beyond 2026.5.29 immediately.
* Restrict access to the NullHub management API (/api/*) to local loopback interfaces only.
* Monitor webserver logs for HTTP requests to /api/* paths originating from external IP addresses that lack 'Authorization' headers.
