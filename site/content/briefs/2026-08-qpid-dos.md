---
title: Denial of Service in Apache Qpid Broker-J via Uncontrolled Recursion
slug: 2026-08-qpid-dos
description: Apache Qpid Broker-J versions through 10.0.1 are vulnerable to a pre-authentication denial of service attack where an attacker triggers a StackOverflowError through crafted type nesting.
date: "2026-08-06T19:26:24Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:apache:qpid_broker-j:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - cve-2026-68073
  - apache
vendors:
  - Apache Software Foundation
products:
  - Apache Qpid Broker-J
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A pre-authentication attacker could leverage type nesting to cause a StackOverflowError potentially leading to denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-68073
    cvss: 7.5
    epss: 0.00193
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-68073
  - https://lists.apache.org/thread/djz1gnrk882vzjo8rykyf9bnywqbvwwr
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Apache Qpid Broker-J to 10.1.0
      owner: IT Operations
      due: 48h
      evidence: Users are recommended to upgrade to version 10.1.0, which fixes the issue.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to Broker-J ports to known administrative/client subnets
      owner: IT Operations
      addresses: CVE-2026-68073
      evidence: The vulnerability is triggerable pre-authentication.
---

Apache Qpid Broker-J versions through 10.0.1 contain a vulnerability (CVE-2026-68073) classified as CWE-674 (Uncontrolled Recursion). This flaw allows a pre-authentication attacker to send specially crafted network requests containing deeply nested data structures to the broker. The processing of these nested types causes the application to enter an uncontrolled recursive state, ultimately resulting in a StackOverflowError. This condition forces the Apache Qpid Broker-J service to crash, creating a denial of service (DoS) condition. The vulnerability affects the AMQP 1-0 protocol implementation within the broker.

## Impact

Successful exploitation of this vulnerability results in the complete loss of availability for the targeted Apache Qpid Broker-J service. As the attack is possible without authentication, any actor with network reach to the broker's management or messaging interface can trigger the crash, disrupting critical messaging queues and downstream integrated applications.

## Recommendation

- Upgrade Apache Qpid Broker-J to version 10.1.0 or later immediately to address the underlying recursion logic flaw.
- Evaluate network access controls to ensure the Qpid Broker-J management and messaging ports are restricted to authorized source IP addresses.
- Monitor logs for repeated service restarts or crash dumps consistent with StackOverflowError exceptions in the JVM process.
