---
title: Splunk OpenTelemetry Java Agent RMI Deserialization Vulnerability
slug: 2024-01-splunk-otel-rmi-rce
description: A remote code execution vulnerability exists in splunk-otel-javaagent versions prior to 2.26.1 due to unsafe deserialization in RMI instrumentation, potentially allowing attackers with network access to execute arbitrary code on affected systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rmi
  - deserialization
  - rce
  - javaagent
vendors:
  - Splunk
products:
  - Splunk OpenTelemetry Java Agent
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-h8w2-rv57-vc6f
  - https://github.com/open-telemetry/opentelemetry-java-instrumentation/security/advisories/GHSA-xw7x-h9fj-p2c7
rules:
  - title: Detect Java Process with RMI Enabled via Command Line
    description: Detects java processes running with RMI enabled based on command line arguments, potentially indicating a vulnerable application.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect RMI traffic on non-standard port
    description: Detects network connections to non-standard ports commonly used for RMI traffic, potentially indicating exploitation.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The Splunk Distribution of OpenTelemetry Java Agent, in versions prior to 2.26.1, contains a critical vulnerability related to unsafe deserialization within its RMI instrumentation. Specifically, the RMI instrumentation registers a custom endpoint that deserializes incoming data without proper serialization filters. This can be exploited by an attacker with network access to a JMX or RMI port on a JVM instrumented with the affected agent. Successful exploitation requires the agent to be attached via `-javaagent`, a network-reachable RMI endpoint (like JMX), and the presence of a gadget-chain-compatible library on the classpath. This vulnerability was disclosed on March 26, 2026. Defenders should upgrade to version 2.26.1 or implement the provided workaround immediately.

## Attack Chain

1.  Attacker gains network access to a target system running a vulnerable version of `splunk-otel-javaagent`.
2.  The Splunk OpenTelemetry Java Agent is running with `-javaagent` to enable instrumentation.
3.  An RMI endpoint (e.g., JMX remote port) is exposed and network-reachable.
4.  The attacker crafts a malicious serialized object containing a gadget chain.
5.  The attacker sends the malicious serialized object to the vulnerable RMI endpoint.
6.  The `splunk-otel-javaagent` deserializes the object without proper filtering in its RMI instrumentation.
7.  The gadget chain within the deserialized object is triggered, leading to code execution.
8.  The attacker executes arbitrary commands on the target system with the privileges of the JVM process.

## Impact

Successful exploitation of this vulnerability allows arbitrary remote code execution with the privileges of the user running the instrumented JVM. This can lead to full system compromise, data exfiltration, or denial of service. The impact is considered critical due to the ease of exploitation and the potential for significant damage.

## Recommendation

*   Upgrade to `splunk-otel-javaagent` version 2.26.1 or later to patch the vulnerability.
*   As a workaround, set the system property `-Dotel.instrumentation.rmi.enabled=false` to disable the RMI integration.
*   Monitor JVM processes for unexpected network connections, which could indicate exploitation attempts. Use `network_connection` logs to detect unusual RMI activity.
*   Implement egress filtering to restrict outbound RMI traffic to known and trusted destinations to limit potential damage.
