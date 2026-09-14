---
title: Authentication Bypass in goproxy CONNECT Requests (CVE-2026-91143)
slug: 2026-09-goproxy-auth-bypass
description: The goproxy package through version 15.3 fails to enforce authentication on CONNECT tunnel requests, allowing unauthorized network relay via the proxy.
date: "2026-09-14T23:36:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:goproxy:goproxy:*:*:*:*:*:*:*:*
tags:
  - proxy
  - authentication-bypass
  - cve-2026-91143
vendors:
  - goproxy
products:
  - goproxy (<= 15.3)
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: Attackers can issue CONNECT requests to establish tunnels through the authenticated proxy without providing credentials, enabling arbitrary TCP traffic relay.
    confidence_band: high
cves:
  - id: CVE-2026-91143
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91143
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade goproxy to a version beyond 15.3
      owner: IT Operations
      due: 48h
      evidence: goproxy through 15.3 fails to apply HTTP proxy basic authentication
  mitigation_plan:
    - priority: immediate
      action: Limit access to goproxy instances via network firewalls to known trusted networks
      owner: Network Security
      addresses: CVE-2026-91143
      evidence: Allows unauthenticated remote attackers to establish TCP tunnels
---

The goproxy library (versions up to and including 15.3) contains a critical authentication bypass vulnerability, tracked as CVE-2026-91143. The flaw stems from a failure to validate HTTP proxy basic authentication credentials when processing CONNECT tunnel requests. Under normal configurations, a proxy requiring authentication should intercept all incoming requests, including HTTP CONNECT methods used for establishing tunnels, and verify the user's identity before permitting traffic relay. 

In affected versions, unauthenticated remote attackers can bypass these security requirements by specifically crafting CONNECT requests to tunnel arbitrary TCP traffic. This allows attackers to leverage the proxy as an unauthorized relay to reach restricted internal network segments or to mask the origin of their traffic for external C2 communication. The issue is significant for any infrastructure relying on goproxy as a gateway, as it effectively nullifies access control policies. Defenders should identify goproxy deployments in their environment and update to a patched version that correctly enforces authentication checks for all request types, including tunnels.

## Impact

Successful exploitation allows unauthenticated attackers to establish arbitrary TCP tunnels through the goproxy server. This facilitates unauthorized access to internal resources otherwise protected by the proxy, enables attackers to exfiltrate data through a trusted egress point, and allows for the masking of C2 traffic. Organizations relying on this library for secure gateway, filtering, or inspection services are at risk of complete access control circumvention.

## Recommendation

- Upgrade all instances of the goproxy package to a version beyond 15.3 immediately to ensure CONNECT requests properly trigger authentication headers.
- Review network egress logs for a high volume of CONNECT requests originating from unidentified clients if the proxy is exposed to the internet.
- Implement network-level restrictions using firewall rules to limit which source IP addresses are permitted to reach the goproxy instance if authentication cannot be immediately patched.
