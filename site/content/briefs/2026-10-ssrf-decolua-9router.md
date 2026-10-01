---
title: SSRF Vulnerability in decolua 9Router
slug: 2026-10-ssrf-decolua-9router
description: A server-side request forgery vulnerability in decolua 9Router versions up to 0.5.55 allows remote attackers to manipulate the provider_options.baseUrl argument to trigger unauthorized requests.
date: "2026-10-01T00:37:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:decolua:9router:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - vulnerability
  - web-application
vendors:
  - decolua
products:
  - 9Router (< 0.5.56)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Performing a manipulation of the argument provider_options.baseUrl results in server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-103530
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103530
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade 9Router to version 0.5.56
      owner: IT Operations
      due: 48h
      evidence: Vendor patch recommendation for CVE-2026-103530
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network access for the 9Router service to prevent unauthorized requests to sensitive internal segments
      owner: Network Security
      addresses: CVE-2026-103530
      evidence: SSRF remediation best practice
---

CVE-2026-103530 identifies a server-side request forgery (SSRF) vulnerability affecting decolua 9Router in all versions up to and including 0.5.55. The vulnerability resides within the fetch function of the file src/shared/utils/ssrfGuard.js, which is part of the application's Search Endpoint component. 

An attacker can exploit this flaw by remotely sending a crafted request that manipulates the provider_options.baseUrl argument. This manipulation forces the application to perform unauthorized requests to arbitrary internal or external resources, potentially leading to unauthorized data access, internal service discovery, or interaction with internal APIs that expect requests only from the trusted server environment. Impact is significant given the ability to bypass network segmentation by leveraging the server's context.

## Impact

Successful exploitation allows remote attackers to perform SSRF attacks, potentially leading to unauthorized interaction with internal infrastructure, sensitive service exposure, or exfiltration of metadata from cloud instances or internal systems.

## Recommendation

Upgrade 9Router to version 0.5.56 or later to apply the necessary security patch for the ssrfGuard.js component. Implement network egress filtering on the host running the 9Router service to restrict unauthorized outbound connections to internal segments.
