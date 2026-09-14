---
title: SSRF Vulnerability in tarzan-cms Theme Download Function
slug: 2026-09-tarzan-cms-ssrf
description: An unauthenticated remote SSRF vulnerability exists in the Theme Download Function of tarzan-cms 1.0.0 due to insecure handling of the httpUrl parameter.
date: "2026-09-14T13:33:41Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:taisan:tarzan_cms:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - web-vulnerability
vendors:
  - taisan
products:
  - tarzan-cms (1.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument httpUrl can lead to server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-90710
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90710
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review access logs for suspicious httpUrl parameters pointing to internal subnets
      owner: SOC
      due: 24h
      evidence: CVE-2026-90710 vulnerability details
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network connectivity from the tarzan-cms server
      owner: IT Operations
      addresses: CVE-2026-90710
      evidence: SSRF vulnerability allows arbitrary outbound requests
---

A Server-Side Request Forgery (SSRF) vulnerability has been identified in tarzan-cms version 1.0.0. The flaw resides within the openConnection function of the ThemeService.java file, specifically within the Theme Download component. An unauthenticated remote attacker can exploit this by manipulating the httpUrl argument, causing the server to perform arbitrary outbound HTTP requests. This vulnerability, tracked as CVE-2026-90710, allows attackers to interact with internal network resources, potentially leading to unauthorized data access or service disruption within the hosting infrastructure. The vulnerability has been publicly disclosed, and as of the report date, the maintainers have not issued a patch or response. Defenders should treat this as a high-risk entry point for reconnaissance and potential lateral movement.

## Impact

Successful exploitation allows a remote attacker to force the tarzan-cms application server to make requests to unintended destinations. This can be leveraged to scan internal networks, access sensitive internal APIs or metadata services (like AWS/Azure IMDS), and potentially bypass firewall restrictions. There is currently no vendor patch available, leaving all deployments of version 1.0.0 exposed to active exploitation.

## Recommendation

* Monitor web server logs for requests to the Theme Download endpoint containing suspicious or internal network IP addresses (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or localhost) in the httpUrl parameter.
* Restrict network access to the application server to prevent it from initiating outbound requests to internal resources.
* Implement egress filtering on the application server to permit only necessary outbound traffic to trusted domains or IP ranges.
* Disable the Theme Download functionality if it is not business-critical until a vendor patch is released.
