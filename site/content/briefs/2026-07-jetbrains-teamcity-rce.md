---
title: 'JetBrains TeamCity: Multiple Vulnerabilities Enable Code Execution'
slug: 2026-07-jetbrains-teamcity-rce
description: Multiple vulnerabilities in JetBrains TeamCity allow a remote, authenticated attacker to execute arbitrary program code on the affected system, potentially leading to full compromise of the CI/CD instance and underlying infrastructure.
date: "2026-07-24T10:25:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - code-execution
  - teamcity
  - ci-cd
vendors:
  - JetBrains
products:
  - TeamCity
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A remote, authenticated attacker can exploit multiple vulnerabilities in JetBrains TeamCity to execute arbitrary program code.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2504
---

The German Federal Office for Information Security (BSI) has issued an advisory regarding multiple critical vulnerabilities discovered in JetBrains TeamCity, a widely used continuous integration and continuous delivery (CI/CD) server. These vulnerabilities, when exploited by a remote and authenticated attacker, can lead to arbitrary program code execution on the server. While specific CVEs or exploit details were not provided, the implication of code execution on a CI/CD platform is severe. Successful exploitation could grant an attacker full control over the build environment, access to sensitive source code repositories, credentials, and potentially enable supply chain attacks by injecting malicious code into compiled artifacts. The advisory highlights the importance of immediate patching for organizations relying on TeamCity for their software development pipelines.

## Attack Chain

1. **Initial Access**: A remote attacker obtains valid authentication credentials for a JetBrains TeamCity instance.
2. **Exploitation**: The attacker leverages unspecified vulnerabilities within the authenticated TeamCity session to manipulate server processes or configurations.
3. **Code Injection**: Malicious code is injected into the TeamCity server's environment or directly into a running process.
4. **Arbitrary Code Execution**: The injected code is executed with the privileges of the TeamCity server process on the underlying host operating system.
5. **System Compromise**: The attacker gains full control over the TeamCity server, allowing the execution of arbitrary commands and unauthorized access.
6. **Post-Exploitation Actions**: The attacker may then establish persistence, exfiltrate sensitive data such as source code, build artifacts, or credentials, or move laterally within the network.
7. **Impact**: The CI/CD pipeline and potentially connected production systems are fully compromised, enabling supply chain attacks or significant operational disruption.

## Impact

A successful exploitation of these vulnerabilities would result in the complete compromise of the JetBrains TeamCity server. This level of access allows an attacker to manipulate or steal intellectual property, inject malicious code into software builds, access sensitive development credentials, and launch further attacks against production environments. The pervasive use of TeamCity in software development pipelines means that organizations could face significant data breaches, supply chain disruptions, and reputational damage if their instances are compromised. The potential for widespread impact on customers downstream of affected CI/CD processes is high.

## Recommendation

* Apply all available security updates for JetBrains TeamCity as soon as possible to mitigate these vulnerabilities.
* Ensure strong, multi-factor authentication (MFA) is enforced for all user accounts on your JetBrains TeamCity instances.
* Monitor your TeamCity server logs for any unusual process creation, unexpected outbound network connections from the TeamCity service account, or anomalous file modifications.
