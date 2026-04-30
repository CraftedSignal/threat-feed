---
title: Spinnaker Echo Service Vulnerable to Spring Expression Language Injection
slug: 2026-04-spinnaker-spel
description: Unrestricted access to the JVM via Spring Expression Language (SPeL) in Spinnaker's Echo service allows for arbitrary code execution, enabling attackers to invoke commands and access files.
date: "2026-04-20T21:19:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - spel
  - code-execution
  - cloud
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2026-32613
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32613
rules:
  - title: Detect Spinnaker Echo SpEL Injection Attempts via Web Logs
    description: Detects potential SpEL injection attempts in Spinnaker Echo service by monitoring web server logs for suspicious patterns in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Spinnaker Echo SpEL Injection via POST Request
    description: Detects potential SpEL injection attempts in Spinnaker Echo service POST requests by monitoring web server logs for suspicious patterns in HTTP request bodies.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Spinnaker is an open-source, multi-cloud continuous delivery platform. The Echo service, like other services within Spinnaker, utilizes Spring Expression Language (SPeL) for processing information, specifically concerning expected artifacts. However, versions prior to 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2 did not restrict the context of SPeL to a set of trusted classes, granting full JVM access, unlike Orca. This unrestricted access enables a user to leverage arbitrary Java classes, facilitating deep system access. This vulnerability allows attackers to execute arbitrary commands, access sensitive files, and potentially compromise the entire Spinnaker environment. Defenders should upgrade to patched versions or disable the Echo service as a workaround to mitigate this critical risk.

## Attack Chain

1. An attacker crafts a malicious payload containing a SpEL expression.
2. This payload is submitted to the Echo service via a network request, likely through a specifically crafted API call involving expected artifacts.
3. The Echo service processes the request and evaluates the malicious SpEL expression without proper context restrictions.
4. The SpEL expression leverages Java classes to bypass security controls and gain access to underlying system resources.
5. The attacker uses the unrestricted JVM access to execute arbitrary commands on the server.
6. Successful command execution allows the attacker to read and write files on the system.
7. The attacker leverages file access to obtain sensitive information such as credentials or configuration files.
8. The attacker uses the compromised system to move laterally within the Spinnaker environment or target connected cloud resources. The final objective is likely complete control over the Spinnaker deployment and its connected infrastructure.

## Impact

Successful exploitation of this vulnerability allows for arbitrary code execution on the Spinnaker server. This can lead to complete system compromise, allowing attackers to steal sensitive data, disrupt continuous delivery pipelines, and potentially gain access to connected cloud environments. Due to the critical nature of Spinnaker in managing deployments, a successful attack could severely impact an organization's ability to deploy and maintain applications, potentially leading to significant financial and reputational damage.

## Recommendation

*   Upgrade Spinnaker instances to versions 2026.1.0, 2026.0.1, 2025.4.2, or 2025.3.2 to patch CVE-2026-32613.
*   As a temporary workaround, disable the Echo service entirely until the upgrade can be performed, referencing the vendor documentation for disabling specific Spinnaker services.
*   Monitor web server logs for unusual HTTP requests to the Echo service endpoints, specifically looking for suspicious patterns or attempts to inject SpEL expressions, using the Sigma rule provided below.
