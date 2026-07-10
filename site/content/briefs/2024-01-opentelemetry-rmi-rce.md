---
title: OpenTelemetry RMI Instrumentation Unsafe Deserialization RCE
slug: 2024-01-opentelemetry-rmi-rce
description: A remote code execution vulnerability exists in OpenTelemetry Java agent versions prior to 2.26.1 due to unsafe deserialization in the RMI instrumentation, potentially allowing attackers with network access to execute arbitrary code on vulnerable systems.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - opentelemetry
  - deserialization
vendors:
  - OpenTelemetry
products:
  - OpenTelemetry Java agent
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-xw7x-h9fj-p2c7
rules:
  - title: Detect OpenTelemetry RMI Instrumentation Attempt
    description: Detects potential attempts to exploit the OpenTelemetry RMI instrumentation vulnerability by monitoring for network connections to common RMI ports from unusual processes.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - network_connection
      - windows
  - title: Detect OpenTelemetry RMI System Property Override
    description: Detects attempts to disable OpenTelemetry RMI instrumentation by setting the 'otel.instrumentation.rmi.enabled' system property to 'false'.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenTelemetry is an observability framework providing APIs, SDKs, and tools for collecting telemetry data from applications. A critical vulnerability, CVE-2026-33701, affects OpenTelemetry Java agent versions prior to 2.26.1. The vulnerability stems from the RMI instrumentation registering a custom endpoint that deserializes incoming data without proper serialization filters. This exposes a potential remote code execution (RCE) risk. Successful exploitation requires the OpenTelemetry Java agent to be attached as a Java agent (`-javaagent`), a network-reachable RMI endpoint (e.g., JMX, RMI registry), and the presence of a gadget-chain-compatible library on the classpath. This vulnerability was responsibly disclosed in coordination with Datadog.

## Attack Chain

1. An attacker identifies a target JVM running a vulnerable version of the OpenTelemetry Java agent (prior to 2.26.1).
2. The attacker confirms that the target JVM has a network-reachable RMI endpoint (e.g., JMX remote port).
3. The attacker ensures a gadget-chain-compatible library (e.g., those used in typical Java deserialization attacks) is present on the target's classpath.
4. The attacker crafts a malicious serialized Java object (payload) designed to execute arbitrary code when deserialized. This payload leverages a known gadget chain within the available libraries.
5. The attacker sends the malicious serialized object to the vulnerable RMI endpoint exposed by the OpenTelemetry Java agent's RMI instrumentation.
6. The OpenTelemetry Java agent deserializes the object without proper validation, triggering the gadget chain.
7. The gadget chain executes arbitrary code within the context of the JVM process.
8. The attacker achieves remote code execution, potentially gaining full control of the compromised system.

## Impact

Successful exploitation of CVE-2026-33701 allows for arbitrary remote code execution with the privileges of the user running the instrumented JVM. This could lead to complete system compromise, data theft, or denial of service. Given the widespread use of OpenTelemetry for monitoring, a successful attack could have significant implications for affected organizations.

## Recommendation

*   Upgrade to OpenTelemetry Java agent version 2.26.1 or later to remediate CVE-2026-33701.
*   Apply the provided workaround by setting the system property `-Dotel.instrumentation.rmi.enabled=false` to disable the vulnerable RMI integration.
