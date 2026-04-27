---
title: Unauthenticated Denial-of-Service and Information Disclosure in Podman Desktop
slug: 2026-04-podman-desktop-dos
description: Podman Desktop versions prior to 1.26.2 expose an unauthenticated HTTP server, allowing remote attackers to trigger denial-of-service conditions by exhausting resources and extract sensitive information through verbose error responses.
date: "2026-04-07T21:17:17Z"
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

Podman Desktop, a graphical tool for container and Kubernetes development, is vulnerable to an unauthenticated remote attack in versions prior to 1.26.2. The exposed HTTP server lacks proper connection limits and timeouts, enabling attackers to exhaust file descriptors and kernel memory. This resource exhaustion leads to denial-of-service conditions, potentially crashing the application or freezing the entire host system. Furthermore, verbose error responses from the server inadvertently…
