---
title: Nuclio Java Runtime Vulnerability Leads to Build-Time Remote Code Execution
slug: 2026-07-nuclio-rce
description: Nuclio's Java runtime dashboard API, by default configured with NOP authentication, is vulnerable to remote code execution (CWE-94) where attackers can inject arbitrary Groovy code into the unsanitized `runtimeAttributes.repositories` field, which is directly written into the `build.gradle` file, allowing the injected code to execute during the Gradle configuration phase as root within the build container.
date: "2026-07-16T19:42:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-injection
  - rce
  - template-injection
  - kubernetes
  - ci-cd
  - groovy
vendors:
  - Nuclio
products:
  - Nuclio <= 1.15.27
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Dashboard API runs with NOP authentication by default, so no credentials are required.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can embed a closing brace (`}`) to break out of the `repositories {}` block and append arbitrary Groovy statements that execute unconditionally during the Gradle configuration phase.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Groovy's `List.execute()` extension method (e.g., `['sh', '-c', 'cmd'].execute()`) runs an OS process.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: 'The injected command output confirmed by dynamic testing: `id && hostname && whoami`'
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
    evidence: 'The injected command output confirmed by dynamic testing: `id && hostname && whoami`'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-3v79-m2cg-89ww
iocs:
  - type: string
    value: id && hostname && whoami
ioc_counts:
  string: 1
rules:
  - title: Detect Nuclio Build-Time RCE via Suspicious Shell Command Execution in Gradle
    description: Detects exploitation of the Nuclio build-time RCE vulnerability (GHSA-3v79-m2cg-89ww) by monitoring for suspicious shell command execution (e.g., system enumeration) where a Java process running Gradle is the parent, indicating injected Groovy code execution.
    platform: sigma
    severity: critical
    tactics:
      - discovery
      - execution
    techniques:
      - T1033
      - T1059.004
      - T1059.006
      - T1082
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical vulnerability (CWE-94, Improper Control of Generation of Code) has been discovered in Nuclio's Java runtime, affecting versions up to and including 1.15.27. This flaw enables unauthenticated attackers to achieve remote code execution (RCE) within the build environment. The vulnerability stems from the Dashboard API's default NOP authentication and a lack of input validation on the `runtimeAttributes.repositories` field. Attackers can embed arbitrary Groovy code into this field, which is then unescaped and directly written into the `build.gradle` file during the function build process. This injected code executes unconditionally during the Gradle configuration phase with root privileges inside the builder container, leading to a complete compromise of the build system. The issue was dynamically verified and confirmed to allow commands like `id`, `hostname`, and `whoami` to execute as the root user.

## Attack Chain

1. An unauthenticated attacker sends an HTTP POST request to the Nuclio Dashboard API's `/api/functions` endpoint.
2. The request body includes a malicious `runtimeAttributes.repositories` field within the function definition, containing Groovy code designed to break out of the `repositories {}` block and execute arbitrary commands.
3. The Dashboard API receives the request; due to default NOP authentication, no credentials or input validation are performed on the `runtimeAttributes.repositories` content.
4. The `newBuildAttributes()` function decodes the `runtimeAttributes` without content inspection, allowing the malicious string to pass through.
5. The `createGradleBuildScript()` function uses Go's `text/template` engine to render the `runtimeAttributes.repositories` verbatim into the `build.gradle` file, without any contextual escaping.
6. The generated `build.gradle` file now contains the attacker's injected Groovy code as top-level statements.
7. The build process, executed by `./build-user-handler.sh` inside the `quay.io/nuclio/handler-builder-java-onbuild` container, invokes `gradle tasks` and `gradle userHandler`.
8. During Gradle's configuration phase, the injected Groovy statements are evaluated, executing the attacker's arbitrary commands (e.g., `id && hostname && whoami`) with root privileges (`uid=0`) inside the build container.

## Impact

Successful exploitation of this vulnerability results in unauthenticated remote code execution with root privileges on the Nuclio build container. An attacker can execute arbitrary commands, leading to full compromise of the build environment, potential data exfiltration, supply chain attacks by injecting malicious code into compiled artifacts, or further lateral movement within the hosting Kubernetes cluster. The proof-of-concept demonstrated execution of `id && hostname && whoami` commands, returning `uid=0(root) gid=0(root) groups=0(root)`, confirming maximum privileges.

## Recommendation

* Patch Nuclio deployments immediately to a version greater than 1.15.27 (once available) as this version is confirmed vulnerable.
* Monitor `process_creation` logs on Linux build containers for suspicious shell command execution (e.g., `sh -c` followed by system enumeration commands like `id`, `whoami`, `hostname`) with `java` as a parent process running `gradle`, as described in the detection rule below.
* Implement robust authentication and authorization for the Nuclio Dashboard API, moving away from NOP authentication, to prevent unauthenticated access.
