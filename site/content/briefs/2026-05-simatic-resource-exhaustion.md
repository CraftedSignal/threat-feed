---
title: Siemens SIMATIC CN 4100 Unauthenticated Resource Exhaustion (CVE-2026-22924)
slug: 2026-05-simatic-resource-exhaustion
description: Siemens SIMATIC CN 4100 versions before V5.0 are vulnerable to resource exhaustion due to improper restriction of unauthenticated connections, potentially leading to disruption of operations and unauthorized actions.
date: "2026-05-12T10:18:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - resource-exhaustion
  - dos
  - ics
  - cve-2026-22924
vendors:
  - Siemens
products:
  - SIMATIC CN 4100
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-22924
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22924
  - https://cert-portal.siemens.com/productcert/html/ssa-032379.html
rules:
  - title: Detect SIMATIC CN 4100 Unauthenticated Connection Attempts
    description: Detects potential resource exhaustion attacks against SIMATIC CN 4100 by monitoring for multiple unauthenticated connections.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect CVE-2026-22924 Exploitation - SIMATIC CN 4100 Resource Exhaustion
    description: Detects CVE-2026-22924 exploitation - high volume of network connections to SIMATIC CN 4100 from a single source IP.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A vulnerability, CVE-2026-22924, affects Siemens SIMATIC CN 4100 devices running versions prior to V5.0. This security flaw stems from the application's failure to adequately restrict unauthenticated connections. As a result, an attacker can exploit this weakness to trigger resource exhaustion conditions. By overwhelming the system with unauthenticated requests, a malicious actor could disrupt normal operations, perform unauthorized actions, and compromise both the availability and integrity of the SIMATIC CN 4100 device. Successful exploitation could lead to significant operational downtime and potential data breaches. This vulnerability poses a substantial risk to industrial control systems (ICS) environments relying on SIMATIC CN 4100.

## Attack Chain

1.  Attacker identifies a vulnerable SIMATIC CN 4100 device exposed on the network.
2.  Attacker establishes an unauthenticated connection to the device.
3.  Attacker sends a high volume of requests to a resource-intensive endpoint.
4.  The SIMATIC CN 4100 device attempts to process each request, consuming system resources.
5.  The device's CPU and memory resources become depleted due to the overwhelming number of requests.
6.  Legitimate requests from authorized users are delayed or dropped.
7.  The SIMATIC CN 4100 device becomes unresponsive or crashes, leading to a denial-of-service condition.
8.  Industrial processes relying on the SIMATIC CN 4100 device are disrupted or halted.

## Impact

Successful exploitation of CVE-2026-22924 can result in a denial-of-service condition on the SIMATIC CN 4100 device, disrupting critical industrial processes. This may lead to operational downtime, financial losses, and potential safety hazards. The vulnerability affects all versions of SIMATIC CN 4100 prior to V5.0, potentially impacting a wide range of industrial sectors that rely on these devices for network communication.

## Recommendation

*   Upgrade SIMATIC CN 4100 devices to version V5.0 or later to remediate CVE-2026-22924.
*   Implement network segmentation and access control measures to limit exposure of SIMATIC CN 4100 devices to untrusted networks.
*   Deploy the Sigma rule "Detect SIMATIC CN 4100 Unauthenticated Connection Attempts" to identify suspicious unauthenticated connection patterns to the device.
*   Monitor network traffic to SIMATIC CN 4100 devices for unusually high connection rates and resource consumption.
*   Apply the mitigations recommended by Siemens in their security advisory SSA-032379.
