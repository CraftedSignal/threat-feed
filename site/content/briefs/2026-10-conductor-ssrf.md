---
title: SSRF Vulnerability in Conductor A2AService
slug: 2026-10-conductor-ssrf
description: An SSRF vulnerability in the Conductor-OSS A2AService allows remote attackers to manipulate the agentUrl parameter to force unauthorized internal requests.
date: "2026-10-13T14:36:50Z"
lastmod: "2026-10-13T14:36:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:conductor-oss:conductor:*:*:*:*:*:*:*:*
vendors:
  - Conductor-OSS
products:
  - conductor (<= 3.32.5)
  - Conductor (<= 3.33.0-rc10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-109403
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109403
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109405
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Conductor-OSS to a patched release
      owner: IT Operations
      due: 72h
      evidence: Source advisory regarding vulnerability in <= 3.32.5
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound connectivity for Conductor service to known-good endpoints
      owner: IT Operations
      addresses: CVE-2026-109403
      evidence: SSRF vulnerability allows unauthorized requests
updates:
  - at: "2026-10-13T14:36:58Z"
    level: L2
    summary: added coverage for Conductor (<= 3.33.0-rc10)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109405
---

The Conductor-OSS workflow orchestration platform contains a Server-Side Request Forgery (SSRF) vulnerability in the A2AService component. Specifically, the getAgentCard function within 'ai/src/main/java/org/conductoross/conductor/ai/a2a/A2AService.java' fails to properly sanitize the 'agentUrl' argument. A remote, unauthenticated attacker can supply a malicious URL to this parameter, causing the Conductor server to make unauthorized requests to arbitrary internal or external targets. This vulnerability may be used to probe internal network services, access metadata services in cloud environments, or potentially bypass internal firewall controls. The flaw is present in all versions of Conductor up to and including 3.32.5.

## Impact

Successful exploitation allows an attacker to perform internal reconnaissance, potentially access sensitive cloud metadata services, or interact with services inside the network perimeter that are not otherwise accessible. This could lead to information disclosure or serve as a pivot point for further internal network exploitation.

## Recommendation

1. Upgrade to a version of Conductor-OSS that patches CVE-2026-109403.
2. Implement strict allow-listing for outbound requests originating from the Conductor-OSS application server.
3. Monitor web access logs for anomalous requests to the A2AService component, particularly those containing suspicious internal IP addresses or private URI schemes in the agentUrl parameter.
4. Ensure the Conductor process is running with the least privilege necessary, particularly concerning network egress capabilities.
