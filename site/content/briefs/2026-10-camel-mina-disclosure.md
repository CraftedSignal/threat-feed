---
title: Information Disclosure in Apache Camel camel-mina Component
slug: 2026-10-camel-mina-disclosure
description: CVE-2026-85246 allows remote attackers to trigger route failures in Apache Camel Mina consumers, causing the disclosure of internal exception details, file paths, and hostnames over TCP/UDP sockets.
date: "2026-10-19T12:17:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
tags:
  - information-disclosure
  - apache-camel
  - cve-2026-85246
vendors:
  - Apache
products:
  - camel-mina (4.0.0-4.18.4, 4.19.0-4.22.0)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: A remote peer able to provoke a failure could read internal detail about the deployment — class and package names, and whatever a message or nested cause carries.
    confidence_band: high
cves:
  - id: CVE-2026-85246
    cvss: 5.3
references:
  - https://camel.apache.org/security/CVE-2026-85246.html
  - https://issues.apache.org/jira/browse/CAMEL-24476
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all Apache Camel instances using the mina component to version 4.18.5, 4.22.1, or 4.23.0.
      owner: IT Operations
      due: 48h
      evidence: Fixed versions 4.18.5, 4.22.1, 4.23.0
  mitigation_plan:
    - priority: immediate
      action: Implement a global onException handler to suppress exception propagation in the Mina consumer.
      owner: Development Team
      addresses: CVE-2026-85246
      evidence: 'Mitigation if you cannot upgrade: Add an onException handler'
---

Apache Camel versions using the `camel-mina` component are vulnerable to an information disclosure flaw (CVE-2026-85246). The vulnerability exists within the `MinaConsumer` class, which incorrectly writes `exchange.getException()` directly back to the remote peer when an exchange process fails. In scenarios using a textline codec, this exposes the exception class name and message; when using an object codec, it exposes the serialized exception and its cause chain.

An attacker can provoke a route failure by sending crafted requests, effectively forcing the application to leak sensitive internal deployment data, including server paths, hostnames, and database configuration details. This issue affects versions from 4.0.0 before 4.18.5, and 4.19.0 before 4.22.1. A proof-of-concept reproducer is publicly available, highlighting the ease with which these details can be harvested over a socket.

## Attack Chain

1. Attacker identifies a network service utilizing `camel-mina` as a consumer for TCP or UDP traffic.
2. Attacker crafts an input payload designed to force a processing failure within the Camel route.
3. Attacker initiates a socket connection to the target service and transmits the crafted payload.
4. The `MinaConsumer` component attempts to process the exchange, triggering an internal `IllegalStateException` or other processing error.
5. The application fails to handle the exception locally and instead writes the raw exception object or string representation back to the remote peer over the established socket.
6. The attacker reads the server's response, extracting the leaked stack trace, configuration file paths, or host network details contained within the exception message.
7. The attacker uses the gathered internal intelligence to inform further targeted exploitation or lateral movement.

## Impact

Successful exploitation results in the leakage of sensitive internal information. This allows unauthorized actors to map internal network infrastructure, identify sensitive local file paths (e.g., secret configuration locations), and gain insight into the backend deployment architecture, significantly reducing the effort required for subsequent attacks.

## Recommendation

1. Upgrade to Apache Camel versions 4.18.5, 4.22.1, or 4.23.0 to resolve the vulnerability.
2. For environments where immediate upgrades are not feasible, implement an `onException` handler in all Camel routes using Mina to intercept errors and ensure the response body is explicitly set, preventing the framework from writing the raw exception back to the client.
3. If using `camel-mina` configurations, verify the use of the new `muteException` consumer option, which defaults to `true` in patched versions, and ensure it is not manually set to `false`.
