---
brief_id: brief-2026-11-06-civetweb-uaf
event_id: brief-2026-11-06-civetweb-uaf
revision: 1
activity_at: "2026-11-06T21:29:08Z"
title: 'CivetWeb: Use-after-free in handle_http2 (CVE-2026-124040)'
slug: 2026-11-civetweb-uaf
description: CivetWeb versions through 1.16 contain a use-after-free vulnerability in the handle_http2 function that may allow unauthenticated remote attackers to bypass access control or cause a denial of service.
date: "2026-11-06T21:29:08Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:civetweb:civetweb:*:*:*:*:*:*:*:*
vendors:
  - CivetWeb
products:
  - CivetWeb (<= 1.16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated remote attackers can send a later HEADERS frame omitting these pseudo-headers to influence request method or path seen by access rules.
    confidence_band: high
cves:
  - id: CVE-2026-124040
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124040
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify CivetWeb deployments and verify current configuration for HTTP/2.
      owner: IT Operations
      due: 48h
      evidence: CivetWeb through 1.16, when built with USE_HTTP2 and enable_http2 on, contains a use-after-free vuln.
  hunt_leads:
    - lead: Identify repeated application crashes or service restarts in CivetWeb logs.
      technique_id: T1068
      data_needed:
        - Web server error logs
        - System crash reports
        - HTTP/2 traffic logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Unauthenticated remote attackers can ... crash the server.
  mitigation_plan:
    - priority: immediate
      action: Disable HTTP/2 in CivetWeb configuration (enable_http2 = off) until a patched version is available.
      owner: IT Operations
      addresses: CVE-2026-124040
      evidence: vulnerability exists when ... enable_http2 on
---

CivetWeb through 1.16 is vulnerable to a use-after-free in the handle_http2() function when the server is compiled with USE_HTTP2 and the enable_http2 configuration is set to on. The vulnerability occurs because the server retains pointers to freed :method and :path pseudo-headers. An unauthenticated attacker can exploit this by sending a crafted HEADERS frame that omits these pseudo-headers, potentially leading to server crashes or the manipulation of request methods and paths to bypass configured access rules.

## Impact
Remote unauthenticated attackers may cause a service crash (denial of service) or influence the internal request processing state to bypass access control restrictions.

## Recommendation
- Inventory systems running CivetWeb to determine if the USE_HTTP2 build flag is active and enable_http2 is configured.
- Disable HTTP/2 support in the CivetWeb configuration if it is not required for production services.
- Monitor vendor security bulletins for the release of a patched version of CivetWeb and prioritize deployment.
