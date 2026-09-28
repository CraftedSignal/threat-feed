---
title: Server-Side Request Forgery in OctoberCMS
slug: 2026-09-octobercms-ssrf
description: An unauthenticated server-side request forgery (SSRF) vulnerability in OctoberCMS allows remote attackers to manipulate the realSourcePath argument to perform unauthorized internal network requests.
date: "2026-09-28T06:47:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:octobercms:octobercms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - ssrf
vendors:
  - OctoberCMS
products:
  - OctoberCMS (<= 4.1.19, <= 4.2.25, <= 4.3.4)
cves:
  - id: CVE-2026-100909
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100909
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OctoberCMS to 4.3.5 or 4.4.0
      owner: IT Operations
      due: 24h
      evidence: Source states upgrading is sufficient to resolve the issue.
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound server egress to internal CIDR ranges
      owner: IT Operations
      addresses: CVE-2026-100909
      evidence: Mitigates SSRF impact by blocking internal network scanning.
---

OctoberCMS versions up to 4.1.19, 4.2.25, and 4.3.4 contain a server-side request forgery (SSRF) vulnerability. The flaw exists within the getSourcePathForResize function located in modules/system/classes/ResizeImages.php. An attacker can supply a malicious value to the realSourcePath argument, which is processed by the application without sufficient validation, leading to SSRF. This vulnerability allows remote, unauthenticated actors to force the OctoberCMS server to initiate arbitrary HTTP requests to internal or external resources. Given the availability of public exploit information, this represents a significant risk for organizations hosting OctoberCMS instances. Defenders should immediately prioritize patching to version 4.3.5 or 4.4.0, which includes the necessary fix (patch ID 0e9736aa2c6d6bd3d60ff6ef9e0b4d32ce387f58) to restrict path access.

## Impact

Successful exploitation allows an attacker to bypass firewalls and access internal services reachable from the OctoberCMS host, potentially leading to unauthorized information disclosure or interaction with internal APIs. The vulnerability affects all users of the specified vulnerable versions, exposing the web infrastructure to unauthorized server-side requests.

## Recommendation

* Patch OctoberCMS instances to version 4.3.5 or 4.4.0 immediately to apply the patch identified by 0e9736aa2c6d6bd3d60ff6ef9e0b4d32ce387f58.
* Monitor webserver access logs for POST requests to resize functionality endpoints containing suspicious file paths or internal IP addresses in query parameters.
* Implement strict egress filtering on the web server to block outbound connections to internal network segments (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and sensitive cloud metadata endpoints (169.254.169.254).
