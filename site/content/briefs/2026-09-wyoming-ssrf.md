---
title: SSRF Vulnerability in Wyoming API
slug: 2026-09-wyoming-ssrf
description: Wyoming versions prior to 1.10.2 contain a server-side request forgery (SSRF) vulnerability that allows unauthenticated remote attackers to redirect outbound API connections to arbitrary network targets.
date: "2026-09-01T21:08:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wyoming:wyoming:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - web-vulnerability
vendors:
  - Wyoming
products:
  - Wyoming (< 1.10.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Wyoming before 1.10.2 contains a server-side request forgery vulnerability that allows unauthenticated attackers with network access to force outbound connections.
    confidence_band: high
cves:
  - id: CVE-2026-8712
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8712
rules:
  - title: Detect CVE-2026-8712 Exploitation - SSRF in Wyoming API
    description: Detects exploitation of CVE-2026-8712 by identifying malicious 'uri' query parameters containing unauthorized protocols directed at the Wyoming API.
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
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Wyoming to version 1.10.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Source states Wyoming before 1.10.2 is vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Implement egress filtering on the host and restrict API access to trusted segments.
      owner: Network Security
      addresses: CVE-2026-8712
---

Wyoming versions prior to 1.10.2 are susceptible to a server-side request forgery (SSRF) vulnerability (CVE-2026-8712). The flaw resides in the handling of the 'uri' query parameter within the application's HTTP API. An unauthenticated attacker with network access to the API can craft malicious requests to endpoints including /api/info, /api/speech-to-text, and /api/text-to-speech. By supplying an arbitrary URI using 'tcp://' or 'unix://' protocols, an attacker can override the server-configured backend settings, forcing the application to initiate unauthorized outbound connections. This capability allows attackers to bypass network perimeters, perform reconnaissance on internal services, or interact with sensitive endpoints that are otherwise unreachable from the public internet. Given the potential for lateral movement and access to internal data, this vulnerability represents a significant risk for deployments exposed to untrusted networks.

## Impact

Successful exploitation allows unauthenticated attackers to perform server-side request forgery, potentially leading to unauthorized interaction with internal services or restricted network infrastructure. If exploited, an attacker could gain insights into internal network topology, extract information from local services, or potentially trigger further downstream vulnerabilities, depending on the environment where Wyoming is deployed.

## Recommendation

1. Upgrade all instances of Wyoming to version 1.10.2 or later to remediate the SSRF vulnerability in the API.
2. Implement network segmentation to restrict access to the Wyoming HTTP API endpoints to trusted IP addresses only.
3. Deploy egress filtering on the host machine running Wyoming to limit outbound connections to only authorized internal backend services or external destinations.
4. Monitor web access logs for unusual 'uri' parameters containing 'tcp://' or 'unix://' prefixes directed at /api/info, /api/speech-to-text, or /api/text-to-speech.
