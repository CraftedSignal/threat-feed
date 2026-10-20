---
brief_id: brief-2026-10-camel-saga-hijacking
event_id: brief-2026-10-camel-saga-hijacking
revision: 1
activity_at: "2026-10-20T14:43:09Z"
title: 'Apache Camel: Saga processor header hijacking (CVE-2026-85312)'
slug: 2026-10-camel-saga-hijacking
description: An input validation vulnerability in Apache Camel’s SagaProcessor allows unauthorized actors to hijack saga associations via the Long-Running-Action header, potentially leading to incorrect compensation or workflow manipulation.
date: "2026-10-20T14:43:09Z"
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
tags:
  - camel
  - middleware
  - vulnerability
  - cve-2026-85312
vendors:
  - Apache
products:
  - camel-core (4.0.0-4.18.4, 4.19.0-4.22.0)
  - camel-spring-boot (4.0.0-4.22.0)
  - camel-quarkus-saga (4.0.0-4.22.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An external sender supplies the unprefixed Long-Running-Action header on an inbound message to a route running the saga EIP.
    confidence_band: high
cves:
  - id: CVE-2026-85312
    cvss: 4.8
    epss: 0.00312
    kev_status: "false"
references:
  - https://camel.apache.org/security/CVE-2026-85312.html
  - https://issues.apache.org/jira/browse/CAMEL-24449
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade affected Apache Camel products to version 4.18.5, 4.22.1, or 4.23.0
      owner: IT Operations
      due: 72h
      evidence: Fixed versions 4.18.5, 4.22.1, 4.23.0 listed in security advisory
  mitigation_plan:
    - priority: immediate
      action: Apply removeHeaders("Long-Running-Action") to all untrusted consumer routes
      owner: IT Operations
      addresses: CVE-2026-85312
      evidence: Official mitigation provided by Apache security advisory
---

Apache Camel versions 4.x before 4.18.5 and 4.19.0 through 4.22.0 are vulnerable to a saga hijacking flaw identified as CVE-2026-85312. The vulnerability resides in the `SagaProcessor` component, which improperly trusts the `Long-Running-Action` message header when determining the current saga coordinator. Because this header lacks a 'Camel' prefix, it is not stripped by standard consumer header filters, allowing an external sender to inject the header into inbound messages.

By supplying a specific identifier in the `Long-Running-Action` header, an attacker can influence which saga an exchange joins. This allows the attacker to associate their request with an existing long-running action initiated by another party or force the system to perform compensation actions incorrectly. This exposure is limited to deployments actively utilizing the Saga EIP. Apache has released patches in versions 4.18.5 and 4.22.1 to ensure the header is only consulted if the configured saga service explicitly supports the protocol.

## Impact

Successful exploitation allows an unauthorized party to manipulate long-running transaction workflows within an Apache Camel application. This can result in unauthorized participation in sagas, misrouting of transactions, or the execution of compensation logic for actions the attacker did not initiate. The impact is significant for financial or enterprise integration workflows where saga consistency and transaction integrity are required.

## Recommendation

1. Upgrade all Apache Camel installations to version 4.18.5, 4.22.1, or 4.23.0 to incorporate the fix for CVE-2026-85312.
2. For environments running Camel Quarkus, upgrade to version 3.40.0 or later to receive the patched Camel 4.22.1 core.
3. If immediate patching is not possible, implement a temporary mitigation at the trust boundary by configuring consumer routes to strip the `Long-Running-Action` header using `removeHeaders("Long-Running-Action")`.
4. Audit existing saga-enabled routes to determine if they are exposed to untrusted external input.
