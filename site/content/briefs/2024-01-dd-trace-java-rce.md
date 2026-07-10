---
title: dd-trace-java RMI Deserialization Remote Code Execution Vulnerability
slug: 2024-01-dd-trace-java-rce
description: A remote code execution vulnerability exists in dd-trace-java versions prior to 1.60.3 due to unsafe deserialization in the RMI instrumentation, potentially allowing attackers with network access to a JMX or RMI port to execute arbitrary code on affected systems.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - deserialization
  - dd-trace-java
  - java
vendors:
  - Datadog
products:
  - dd-trace-java
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1212
    technique_name: Remote Service Session Hijacking
references:
  - https://github.com/advisories/GHSA-579q-h82j-r5v2
rules:
  - title: Detect dd-trace-java RMI Deserialization Attempt
    description: Detects potential attempts to exploit the dd-trace-java RMI deserialization vulnerability by identifying suspicious serialized objects in network traffic to JMX/RMI ports.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1212
    data_sources:
      - network_connection
      - windows|linux|macos
  - title: Detect dd-trace-java RMI Disabled via Environment Variable
    description: Detects when the DD_INTEGRATION_RMI_ENABLED environment variable is set to false, which is a recommended workaround for the dd-trace-java RMI deserialization vulnerability. This can help identify systems where the workaround has been applied.
    platform: sigma
    severity: informational
    tactics:
      - defensive_evasion
    data_sources:
      - process_creation
      - linux|windows
rules_count: 2
---

A critical vulnerability exists in the dd-trace-java library, specifically within its RMI instrumentation. Versions prior to 1.60.3 are susceptible to unsafe deserialization of incoming data on a custom RMI endpoint, potentially leading to remote code execution. This vulnerability affects applications using dd-trace-java as a Java agent on Java 16 or earlier. The exploitability hinges on three conditions: the agent being attached, a JMX/RMI port being explicitly configured and network-reachable, and the presence of a gadget-chain-compatible library on the classpath. This vulnerability, responsibly disclosed by Mohamed Amine ait Ouchebou (mrecho) (Indiesecurity) via the Datadog bug bounty program, poses a significant threat to applications instrumented with vulnerable versions of dd-trace-java. Successful exploitation grants the attacker the privileges of the user running the instrumented JVM.

## Attack Chain

1. The attacker identifies a target system running dd-trace-java as a Java agent on JDK 16 or earlier, with a JMX/RMI port exposed.
2. The attacker probes the exposed JMX/RMI port (typically configured via `-Dcom.sun.management.jmxremote.port`).
3. The attacker crafts a malicious serialized payload using a gadget-chain-compatible library present on the target's classpath.
4. The attacker sends the malicious serialized payload to the vulnerable RMI endpoint registered by dd-trace-java.
5. The vulnerable RMI instrumentation in dd-trace-java deserializes the incoming data without proper validation or serialization filters.
6. The deserialization process triggers the gadget chain within the malicious payload.
7. The gadget chain executes arbitrary code on the target system, granting the attacker control.
8. The attacker gains remote code execution with the privileges of the user running the instrumented JVM.

## Impact

Successful exploitation of this vulnerability allows for arbitrary remote code execution with the privileges of the user running the instrumented JVM. This could lead to complete system compromise, data theft, denial of service, or further lateral movement within the network. The scope of impact depends on the exposure of JMX/RMI ports and the prevalence of vulnerable dd-trace-java versions within an organization's infrastructure. This vulnerability can affect any application instrumented by dd-trace-java on JDK 16 or earlier where the aforementioned conditions are met.

## Recommendation

*   For JDK >= 8u121 < JDK 17: Upgrade to dd-trace-java version 1.60.3 or later to patch the vulnerability.
*   For JDK < 8u121 and earlier where serialization filters are not available: Set the environment variable `DD_INTEGRATION_RMI_ENABLED=false` to disable the RMI integration as a workaround.
*   Identify all systems running dd-trace-java versions prior to 1.60.3 to prioritize patching or applying the workaround.
*   Monitor network connections to JMX/RMI ports (typically TCP ports) for suspicious activity.
*   Deploy the Sigma rule "Detect dd-trace-java RMI Deserialization Attempt" to detect attempts to exploit this vulnerability by identifying suspicious serialized objects in network traffic to JMX/RMI ports.
*   Consider implementing network segmentation to limit access to JMX/RMI ports from untrusted networks.
