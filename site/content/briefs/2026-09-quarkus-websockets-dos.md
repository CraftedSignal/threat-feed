---
title: Denial of Service Vulnerability in Quarkus WebSockets Next
slug: 2026-09-quarkus-websockets-dos
description: A vulnerability in quarkus-websockets-next allows a remote attacker to cause a Denial of Service via heap exhaustion by streaming WebSocket messages faster than the application can process them.
date: "2026-09-17T15:59:57Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:redhat:quarkus:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - java
  - application-security
vendors:
  - Red Hat
products:
  - Quarkus (quarkus-websockets-next)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This vulnerability allows a remote attacker to cause a Denial of Service (DoS) by streaming messages over a single connection faster than the application can process them.
    confidence_band: high
cves:
  - id: CVE-2026-87742
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87742
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Audit applications for usage of quarkus-websockets-next
      owner: Security Engineering
      due: 48h
      evidence: CVE-2026-87742 identified in quarkus-websockets-next
  mitigation_plan:
    - priority: immediate
      action: Upgrade Quarkus to the vendor-recommended patched release
      owner: IT Operations
      addresses: CVE-2026-87742
      evidence: NVD vulnerability entry
---

A vulnerability exists in the quarkus-websockets-next component of the Red Hat Quarkus framework, identified as CVE-2026-87742. This issue stems from the lack of read backpressure and the implementation of unbounded message buffering within the WebSocket handling logic. A remote, unauthenticated attacker can exploit this flaw by flooding a single WebSocket connection with high-frequency messages. Because the application fails to regulate the data ingress rate, the incoming messages accumulate in the system's memory heap. This rapid, uncontrolled allocation of memory leads to a java.lang.OutOfMemoryError, ultimately forcing the JVM to crash and resulting in a complete Denial of Service for the affected service.

## Impact

Successful exploitation results in the immediate unavailability of the application due to a JVM crash. This Denial of Service vulnerability impacts any service utilizing the vulnerable quarkus-websockets-next extension. Depending on the service architecture, this may lead to significant operational disruption for organizations relying on the affected Quarkus-based applications.

## Recommendation

1. Identify all applications currently utilizing the quarkus-websockets-next extension within the environment.
2. Monitor application logs and system resource telemetry for sudden, high-frequency WebSocket traffic volume and recurring JVM heap usage spikes.
3. Consult Red Hat security advisories for the specific patched version of Quarkus and prioritize applying updates to all vulnerable nodes.
