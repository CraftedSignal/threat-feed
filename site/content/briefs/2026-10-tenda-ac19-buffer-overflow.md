---
brief_id: brief-2026-10-21-tenda-ac19-buffer-overflow
event_id: brief-2026-10-21-tenda-ac19-buffer-overflow
revision: 1
activity_at: "2026-10-21T04:16:27Z"
title: 'Tenda AC19: Stack-based buffer overflow in httpd web service (CVE-2026-113744)'
slug: 2026-10-tenda-ac19-buffer-overflow
description: Tenda AC19 firmware version 16.03.10.07 is vulnerable to a remote stack-based buffer overflow in the httpd web management service, allowing unauthenticated attackers to trigger a crash or achieve arbitrary code execution via the firewallEn parameter.
date: "2026-10-21T04:16:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:o:tenda:ac19_firmware:16.03.10.07:*:*:*:*:*:*:*
tags:
  - cve-2026-113744
  - buffer-overflow
  - router-vulnerability
  - rce
vendors:
  - Tenda
products:
  - AC19 (16.03.10.07)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-113744
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113744
rules:
  - title: Detects CVE-2026-113744 Exploitation - Potential Buffer Overflow in /goform/SetFirewallCfg
    description: Detects HTTP POST requests to the Tenda AC19 /goform/SetFirewallCfg endpoint, which is the vector for CVE-2026-113744.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and isolate any Tenda AC19 routers exposed to the public internet.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is exploitable remotely.
  mitigation_plan:
    - priority: immediate
      action: Apply firmware updates or restrict management interface access.
      owner: IT Operations
      addresses: CVE-2026-113744
      evidence: CVE-2026-113744
---

A critical security vulnerability, CVE-2026-113744, has been identified in Tenda AC19 routers running firmware version 16.03.10.07. The vulnerability exists within the httpd Web Management Service, specifically in the formSetFirewallCfg function located in the /goform/SetFirewallCfg file. An attacker can exploit this remotely by sending a maliciously crafted HTTP request containing an oversized payload within the 'firewallEn' parameter. This manipulation results in a stack-based buffer overflow, which can lead to a denial-of-service condition or potential arbitrary code execution with the privileges of the web service. As this service is internet-facing by design and public exploit code is available, the risk to affected devices is significant.

## Impact

Successful exploitation of this vulnerability allows for unauthenticated remote code execution or a persistent denial-of-service state on the affected Tenda AC19 routers. This compromises the integrity and availability of the local network perimeter, as the device acts as the primary gateway. Targeted organizations using this hardware model in remote offices or small business environments are at high risk of unauthorized access.

## Recommendation

1. Review internal inventory to identify any Tenda AC19 devices running firmware version 16.03.10.07.
2. If an official firmware patch is provided by Tenda, apply it immediately across the entire fleet of identified devices.
3. In the absence of an immediate patch, restrict access to the web management interface of the router to trusted internal IP addresses only.
4. Ensure that the web management service is not exposed to the public internet by disabling remote administration features.
5. Monitor perimeter firewall logs for unusual POST requests targeting the /goform/SetFirewallCfg endpoint.
