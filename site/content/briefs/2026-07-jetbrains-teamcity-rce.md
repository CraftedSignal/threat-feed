---
title: Critical Unauthenticated RCE in JetBrains TeamCity
slug: 2026-07-jetbrains-teamcity-rce
description: A critical insecure deserialization vulnerability (CVE-2026-63077) in JetBrains TeamCity allows unauthenticated remote attackers to execute arbitrary system commands via the agent polling protocol.
date: "2026-07-29T16:47:46Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - vulnerability
  - rce
  - cicd
  - jetbrains
vendors:
  - JetBrains
products:
  - TeamCity On-Premises
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker with HTTP(S) access to a TeamCity server can exploit the agent polling protocol to bypass authentication checks and execute arbitrary operating system commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: attackers... can... execute arbitrary operating system commands with the privileges of the TeamCity server process.
    confidence_band: high
cves:
  - id: CVE-2026-63077
    cvss: 9.8
    epss: 0.00649
references:
  - https://www.rapid7.com/blog/post/etr-cve-2026-63077-critical-unauthenticated-remote-code-execution-in-jetbrains-teamcity
  - https://blog.jetbrains.com/teamcity/2026/07/cve-2026-63077/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63077
---

On July 27, 2026, JetBrains disclosed CVE-2026-63077, a critical deserialization vulnerability affecting all versions of TeamCity On-Premises. With a CVSS score of 9.8, the vulnerability allows an unauthenticated remote attacker to interact with the server's agent polling protocol to bypass authentication mechanisms. By sending specifically crafted payloads, an attacker can achieve remote code execution (RCE) with the privileges of the underlying TeamCity server process. 

This vulnerability presents a severe risk to CI/CD environments, as successful exploitation enables attackers to harvest stored credentials, manipulate build artifacts, and gain persistent access to the broader development infrastructure. While JetBrains reported no evidence of active exploitation at the time of disclosure, the simplicity of the attack vector makes patching or applying the provided security plugin an immediate requirement for all on-premises deployments.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing TeamCity instances.
2. Attacker establishes a connection to the TeamCity server using the agent polling protocol.
3. Attacker sends a malicious, serialized payload to the targeted endpoint.
4. The TeamCity server deserializes the untrusted data without sufficient validation.
5. The deserialization process triggers execution of arbitrary code within the context of the server process.
6. Attacker gains initial access and executes OS commands to dump credentials or deploy further malicious payloads.
7. Attacker uses compromised credentials to move laterally into the CI/CD pipeline.
8. Attacker compromises build processes or exfiltrates proprietary source code from the build environment.

## Impact

Successful exploitation allows for full system compromise of the TeamCity server, enabling attackers to read sensitive build configurations, steal hardcoded credentials, and inject malicious code into CI/CD pipelines. This could lead to a wide-scale supply chain attack, impacting software integrity for downstream users of the organization's products.

## Recommendation

Prioritize patching or applying workarounds to mitigate CVE-2026-63077:
- Upgrade TeamCity On-Premises to version 2025.11.7 or 2026.1.3 immediately.
- If upgrading is not feasible, apply the JetBrains security patch plugin for all versions 2017.1 and later.
- Restrict network access to TeamCity servers via firewall rules to ensure only authorized agent IPs and management workstations have ingress access to the polling protocol.
