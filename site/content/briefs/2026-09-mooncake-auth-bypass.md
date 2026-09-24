---
title: Authorization Bypass in kvcache-ai Mooncake RPC Path Handler
slug: 2026-09-mooncake-auth-bypass
description: An authorization bypass vulnerability in the UnmountSegment function of the kvcache-ai mooncake RPC Path Handler allows unauthenticated remote attackers to perform unauthorized operations by manipulating client_id or segment_id arguments.
date: "2026-09-24T00:45:44Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:kvcache_ai:mooncake:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-access
  - rpc
vendors:
  - kvcache-ai
products:
  - mooncake (<= 0.3.13.post1)
cves:
  - id: CVE-2026-96762
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96762
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to the RPC Path Handler interface via firewalls.
      owner: IT Operations
      due: 24h
      evidence: Remote exploitation is possible and public exploits exist.
  hunt_leads:
    - lead: Identify unauthorized calls to UnmountSegment via RPC logs.
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability exists in the UnmountSegment function.
  mitigation_plan:
    - priority: immediate
      action: Isolate vulnerable mooncake instances from the public internet.
      owner: IT Operations
      addresses: CVE-2026-96762
      evidence: Unauthenticated remote exploitation is possible.
---

CVE-2026-96762 identifies an authorization bypass vulnerability affecting kvcache-ai mooncake versions up to and including 0.3.13.post1. The flaw exists within the UnmountSegment function of the RPC Path Handler component. Due to insufficient validation of input arguments, an attacker can manipulate the client_id or segment_id parameters during an RPC request to circumvent security controls. This vulnerability allows for remote exploitation, potentially enabling unauthorized access to or manipulation of cached segments. A proof-of-concept exploit has been publicly disclosed, increasing the risk of active exploitation. The vendor has not provided a response or a security patch as of the time of disclosure, leaving implementations of mooncake in the affected versions currently vulnerable to unauthorized administrative actions.

## Impact

Successful exploitation of this vulnerability allows unauthorized remote actors to interact with the RPC Path Handler in unintended ways, potentially leading to unauthorized data modification or segment unmounting. This poses a significant risk to the integrity and availability of services relying on mooncake for caching. As public exploits are available, the probability of targeting by opportunistic attackers is elevated.

## Recommendation

* Monitor network traffic directed at the mooncake RPC endpoints for anomalous requests containing modified client_id or segment_id parameters.
* Implement strict network segmentation to restrict access to the RPC interface to trusted internal systems only.
* Given the lack of a vendor patch, evaluate the necessity of the mooncake service and consider isolating or disabling the service if it cannot be adequately protected behind authentication or network controls.
* Audit access logs for the RPC Path Handler to identify any unusual UnmountSegment calls that deviate from standard service behavior.
