---
title: Unauthenticated Denial-of-Service and Information Disclosure in Podman Desktop
slug: 2026-04-podman-desktop-dos
description: Podman Desktop versions prior to 1.26.2 expose an unauthenticated HTTP server, allowing remote attackers to trigger denial-of-service conditions by exhausting resources and extract sensitive information through verbose error responses.
date: "2026-04-07T21:17:17Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - podman-desktop
  - denial-of-service
  - information-disclosure
  - cve-2026-34045
  - linux
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-34045
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34045
rules:
  - title: Detect Excessive HTTP Requests to Podman Desktop
    description: Detects potential denial-of-service attempts against Podman Desktop by monitoring for a high number of requests from the same source IP within a short timeframe.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Podman Desktop Error Responses Revealing Internal Paths
    description: Detects potential information disclosure by monitoring for error responses from Podman Desktop containing internal paths.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1592.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Podman Desktop, a graphical tool for container and Kubernetes development, is vulnerable to an unauthenticated remote attack in versions prior to 1.26.2. The exposed HTTP server lacks proper connection limits and timeouts, enabling attackers to exhaust file descriptors and kernel memory. This resource exhaustion leads to denial-of-service conditions, potentially crashing the application or freezing the entire host system. Furthermore, verbose error responses from the server inadvertently disclose internal paths and system details, including usernames on Windows systems. This information leakage facilitates further exploitation attempts. The vulnerability, identified as CVE-2026-34045, requires no authentication or user interaction and is exploitable over a network, making it a significant threat to systems running vulnerable versions of Podman Desktop. Users should update to version 1.26.2 or later to mitigate this risk.

## Attack Chain

1. Attacker identifies a vulnerable Podman Desktop instance running a version prior to 1.26.2 exposed on the network.
2. Attacker connects to the unauthenticated HTTP server exposed by Podman Desktop.
3. The attacker sends a large number of HTTP requests without proper connection management.
4. The server fails to enforce connection limits, leading to an exhaustion of available file descriptors on the host system.
5. The attacker sends specially crafted requests designed to trigger resource-intensive operations, consuming excessive kernel memory.
6. As file descriptors and kernel memory are depleted, the Podman Desktop application becomes unresponsive.
7. The system experiences a denial-of-service condition, potentially leading to application crash or a full host freeze.
8. The attacker analyzes verbose error responses to gain insights into internal paths and system details, potentially including usernames on Windows, to prepare for further attacks.

## Impact

Successful exploitation of CVE-2026-34045 can lead to a complete denial-of-service of the Podman Desktop application, disrupting container and Kubernetes development workflows. In severe cases, the entire host system may freeze, requiring a reboot and causing data loss or corruption. The information disclosure aspect of the vulnerability, leaking internal paths and usernames, can aid attackers in crafting more targeted and sophisticated attacks against the compromised system. The lack of authentication makes all installations of vulnerable Podman Desktop versions potential targets, impacting developers and organizations relying on this tool.

## Recommendation

*   Immediately upgrade Podman Desktop to version 1.26.2 or later to patch CVE-2026-34045.
*   Implement network segmentation and firewall rules to restrict access to the Podman Desktop HTTP server only to trusted networks, mitigating external exploitation.
*   Deploy the Sigma rule "Detect Excessive HTTP Requests to Podman Desktop" to identify potential denial-of-service attempts against vulnerable Podman Desktop instances.
*   Monitor webserver logs for unusual HTTP requests and error responses from Podman Desktop, correlating them with potential exploitation attempts. Enable webserver logging to activate the rule above.
