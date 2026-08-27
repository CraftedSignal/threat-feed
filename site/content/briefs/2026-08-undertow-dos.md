---
title: Denial of Service Vulnerability in Undertow WebSocket Implementation
slug: 2026-08-undertow-dos
description: A vulnerability in the Undertow web server's permessage-deflate extension allows remote attackers to trigger a Denial of Service through excessive memory consumption via exponential buffer allocation.
date: "2026-08-27T19:09:50Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - Red Hat
products:
  - Undertow
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This could lead to excessive memory consumption due to the PerMessageDeflateFunction.largerBuffer() method using exponential doubling, resulting in a Denial of Service (DoS) for the affected application.
    confidence_band: high
cves:
  - id: CVE-2026-5680
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5680
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update Undertow library to latest security release for CVE-2026-5680
      owner: IT Operations
      due: 72h
      evidence: NVD vulnerability entry requires software patch for resolution.
  mitigation_plan:
    - priority: immediate
      action: Disable permessage-deflate extension in WebSocket configuration
      owner: IT Operations
      addresses: CVE-2026-5680
      evidence: Source identifies permessage-deflate as the primary exploitation vector.
---

CVE-2026-5680 is a high-severity vulnerability identified in the Undertow web server. The flaw exists within the implementation of the WebSocket permessage-deflate extension, which is responsible for compressing messages to improve network performance. An unauthenticated remote attacker can exploit this by sending specially crafted WebSocket messages that force the `PerMessageDeflateFunction.largerBuffer()` method to perform recursive, exponential memory allocation. This behavior leads to rapid memory exhaustion on the server, resulting in a Denial of Service (DoS) for the affected application. Because the exhaustion occurs at the application level through standard protocol features, it is particularly difficult to distinguish from legitimate high-traffic volume without specific inspection of WebSocket frame metadata and compression negotiation parameters.

## Impact

Successful exploitation results in an application-level Denial of Service, causing the affected service to crash or become unresponsive to legitimate user requests. This vulnerability impacts any system utilizing Undertow with WebSocket support enabled where the permessage-deflate extension is active. Given the common usage of Undertow within various Java-based application frameworks, the potential for service disruption is significant for enterprise environments relying on these components for real-time communication.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Patch the Undertow library to the vendor-provided security update that addresses CVE-2026-5680.
- Monitor web server application logs for spikes in memory usage or frequent service restarts associated with WebSocket endpoints.
- Evaluate current WebSocket configuration and disable the permessage-deflate extension if it is not strictly required for application functionality until patching is complete.
