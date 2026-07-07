---
title: OpenDJ Pre-Auth RCE via Java Deserialization in JMX RMI (CVE-2026-46495)
slug: 2026-07-opendj-pre-auth-rce
description: A critical pre-authentication remote code execution (RCE) vulnerability, CVE-2026-46495, exists in OpenDJ Community Edition affecting versions up to 5.1.0, where a deserialization of untrusted data issue in the JMX RMI connector allows unauthenticated attackers with TCP reachability to the JMX listener to execute arbitrary Java objects, potentially leading to full system compromise.
date: "2026-07-03T11:03:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - java
  - deserialization
  - rce
  - opendj
  - jmx-rmi
  - pre-auth
  - network
vendors:
  - Open Identity Platform
products:
  - OpenDJ Community Edition <= 5.1.0
  - opendj-server-legacy <= 5.1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A Deserialization of Untrusted Data (CWE-502) issue in OpenDJ's JMX RMI connector allows an unauthenticated remote attacker to deserialize arbitrary Java objects on the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Successful exploitation results in unauthenticated Remote Code Execution (RCE), with the severity depending on the runtime classpath and Java version.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-43x2-g84q-fmqx
---

A critical pre-authentication remote code execution (RCE) vulnerability, identified as CVE-2026-46495, impacts OpenDJ Community Edition versions up to 5.1.0. This flaw stems from a deserialization of untrusted data (CWE-502) within OpenDJ's JMX RMI connector, which allows an unauthenticated remote attacker to deserialize arbitrary Java objects on the server. The vulnerability exists because the platform processes attacker-controlled bytes prior to any authentication. While the JMX Connection Handler is disabled by default, it is frequently enabled in production environments for monitoring purposes, significantly expanding the attack surface. Exploitation requires direct TCP reachability to the configured JMX listener and does not necessitate prior authentication, specific privileges, or client certificates. Successful exploitation can lead to complete system compromise, with the specific impact depending on the server's runtime classpath and Java version. This issue was patched in OpenDJ Community Edition version 5.1.1.

## Attack Chain

1.  An unauthenticated remote attacker identifies an internet-accessible OpenDJ server with the JMX Connection Handler enabled, listening for JMX RMI connections.
2.  The attacker crafts a malicious serialized Java object payload designed to execute arbitrary commands upon deserialization.
3.  The attacker establishes a connection to the OpenDJ JMX RMI listener.
4.  The attacker transmits the crafted malicious serialized Java object payload over the JMX RMI connection.
5.  The OpenDJ server, due to the deserialization of untrusted data vulnerability (CVE-2026-46495), processes and deserializes the attacker-controlled bytes before any authentication takes place.
6.  During deserialization, the malicious Java object triggers arbitrary code execution on the underlying operating system within the context of the OpenDJ server process.
7.  The attacker gains unauthenticated Remote Code Execution (RCE) on the server, potentially leading to full system compromise or data exfiltration.

## Impact

This critical vulnerability impacts all OpenDJ Community Edition releases up to 5.1.0 where the JMX Connection Handler is enabled, a common practice for monitoring integrations. Successful exploitation requires TCP reachability to the JMX listener and grants unauthenticated Remote Code Execution (RCE), allowing attackers to run arbitrary code on the server. The severity of the RCE and potential for system compromise depends on the server's runtime classpath and Java version. For example, unauthenticated RCE was specifically demonstrated on OpenDJ 4.4.15 running JDK 11 with Jackson 2.12.6.1, indicating a high potential for severe consequences including data breach, system disruption, or further network lateral movement.

## Recommendation

*   Prioritize patching all affected OpenDJ Community Edition instances to version 5.1.1 or higher immediately to remediate CVE-2026-46495.
*   Review network firewall rules to ensure that the OpenDJ JMX RMI connector port (default 1099, though configurable) is not exposed to untrusted networks or the internet unless absolutely necessary.
*   Disable the JMX Connection Handler if it is not explicitly required for monitoring integrations, as it is disabled by default in OpenDJ.
