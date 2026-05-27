---
title: Yamcs Server-Side Code Injection via Janino Expression Engine
slug: 2026-05-yamcs-rce
description: A server-side code injection vulnerability exists in Yamcs algorithm evaluation engine, allowing an authenticated user with `ChangeMissionDatabase` privilege to achieve Remote Code Execution (RCE) by injecting a malicious Java payload via the Janino compiler.
date: "2026-05-27T00:07:37Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - rce
  - code-injection
  - yamcs
vendors:
  - Yamcs
products:
  - yamcs-core ( < 5.12.7 )
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.008
    technique_name: 'Command and Scripting Interpreter: Java'
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-524g-x36v-9wm6
  - CVE-2026-44632
iocs:
  - type: url
    value: https://<YOUR-WEBHOOK-URL>/$(hostname)_$(whoami)
ioc_counts:
  url: 1
rules:
  - title: Detect CVE-2026-44632 Exploitation — Yamcs Malicious Algorithm Update
    description: Detects CVE-2026-44632 exploitation — An HTTP PATCH request to the MDB override endpoint with a Java Runtime exec call.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.008
    data_sources:
      - webserver
  - title: Detect CVE-2026-44632 Exploitation - Yamcs Webhook Command Execution Attempt
    description: Detects CVE-2026-44632 exploitation — Detects outgoing network connections originating from the Yamcs server to a URL containing hostname and username after a PATCH request.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A server-side code injection vulnerability has been identified in Yamcs, specifically affecting the `org.yamcs.algorithms.JavaExprAlgorithmExecutionFactory` component. This flaw allows an authenticated user with the `ChangeMissionDatabase` privilege to inject arbitrary Java code into the algorithm evaluation engine. The application dynamically compiles and evaluates this user-controlled algorithm text using the Janino compiler, but lacks a secure sandbox to prevent malicious code execution. Exploitation leads to Remote Code Execution (RCE) on the underlying host operating system. Discovered and reported by Pablo Picurelli Ortiz, this vulnerability is present in Yamcs versions prior to 5.12.7.

## Attack Chain

1.  An attacker gains valid credentials to a Yamcs instance with an active processor (e.g., `instance=myproject`, `processor=realtime`).
2.  The attacker authenticates to the Yamcs REST API using the acquired credentials, ensuring they possess the `SystemPrivilege.ChangeMissionDatabase` privilege.
3.  The attacker crafts a malicious Java payload designed to execute arbitrary OS commands. This payload often utilizes `java.lang.Runtime.getRuntime().exec()` to initiate a reverse shell or establish an external webhook connection.
4.  The attacker sends an authenticated HTTP `PATCH` request to the MDB override endpoint, targeting an existing algorithm (e.g., `copySunsensor`). The request body contains the malicious Java code within the `text` field of the algorithm definition.
5.  The Yamcs server receives the `PATCH` request and updates the targeted algorithm's text with the attacker-supplied Java code.
6.  The attacker triggers the evaluation of the modified algorithm. This can be achieved by sending telemetry data that the algorithm depends on, simulating real-world sensor readings.
7.  The Yamcs server employs the Janino `SimpleCompiler` to dynamically compile the injected Java text into a Java class. Due to the absence of a restrictive `ClassLoader`, the compilation process proceeds without any security constraints.
8.  The compiled malicious Java code is executed by the Yamcs server, resulting in arbitrary command execution on the host operating system. This allows the attacker to perform actions such as data exfiltration or lateral movement.

## Impact

Successful exploitation of this vulnerability grants an attacker with application-level configuration privileges full control over the Yamcs server's underlying operating system. This can lead to arbitrary command execution, sensitive data exfiltration, and the potential for lateral movement within the network where the Yamcs server is hosted. The impact is severe, potentially compromising the entire system and its data.

## Recommendation

*   Upgrade Yamcs to version 5.12.7 or later to patch CVE-2026-44632.
*   Implement strict access controls to limit the number of users with the `ChangeMissionDatabase` privilege.
*   Deploy the Sigma rules provided in this brief to detect attempts to inject malicious Java code into Yamcs algorithms.
*   Monitor network traffic for connections to the webhook URL provided in the IOC table.
