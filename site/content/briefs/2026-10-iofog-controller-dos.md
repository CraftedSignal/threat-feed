---
brief_id: brief-2026-10-iofog-controller-dos
event_id: brief-2026-10-iofog-controller-dos
revision: 1
activity_at: "2026-10-20T14:17:33Z"
title: 'Eclipse ioFog Controller: Denial of Service via Unauthenticated Liquid Template Processing (CVE-2026-113619)'
slug: 2026-10-iofog-controller-dos
description: An unauthenticated denial-of-service vulnerability in Eclipse ioFog Controller (versions 3.8.0 through 3.9.1) allows attackers to crash the controller process by sending malicious JSON payloads to template-processing routes.
date: "2026-10-20T14:17:33Z"
type: advisory
types:
  - advisory
severities:
  - low
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
  - cpe:2.3:a:eclipse:iofog_controller:3.8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:eclipse:iofog_controller:3.9.1:*:*:*:*:*:*:*
vendors:
  - Eclipse Foundation
products:
  - ioFog Controller (3.8.0 - 3.9.1)
cves:
  - id: CVE-2026-113619
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113619
rules:
  - title: Detect Potential CVE-2026-113619 Exploitation - DoS Attempts
    description: Detects POST, PUT, or PATCH requests to the ioFog Controller that may be attempting to trigger template-based processing to induce a DoS condition.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch or restrict access to ioFog Controller API
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-113619 report
  mitigation_plan:
    - priority: immediate
      action: Implement WAF/ACL restrictions for ioFog Controller ports
      owner: Network Security
      addresses: CVE-2026-113619
      evidence: NVD vulnerability details
---

Eclipse ioFog Controller versions 3.8.0 through 3.9.1 contain a high-severity vulnerability (CVE-2026-113619) that permits unauthenticated denial-of-service (DoS) attacks. The flaw exists because the application utilizes the Liquid template engine to process request bodies for POST, PUT, and PATCH operations before enforcing authentication or role-based access control (RBAC). 

The security controls in place fail to properly validate bearer tokens or apply rate limiting to these specific routes. By sending a specially crafted, small JSON body, an anonymous attacker can cause the controller process to stall or abort. The resulting disruption impacts the availability of the entire control plane, including agent APIs and in-process WebSocket relays, rendering the ioFog environment unresponsive. Defenders should prioritize patching or implementing network-level access controls to limit access to vulnerable controller endpoints.

## Impact

Successful exploitation results in the loss of control plane availability, effectively disabling management of connected ioFog agents and WebSocket-based telemetry relays. This vulnerability poses a significant risk to distributed edge computing environments relying on ioFog, as the control plane serves as the central orchestration point for fleet operations.

## Recommendation

* Upgrade Eclipse ioFog Controller to a version beyond 3.9.1 once a patch is available.
* Until patching is feasible, implement network-level access control lists (ACLs) to restrict access to the ioFog Controller API to authorized management IP addresses only.
* Enable web application firewall (WAF) or load balancer inspection to identify and block suspicious POST, PUT, and PATCH requests to the controller that contain excessive or malformed JSON payloads.
