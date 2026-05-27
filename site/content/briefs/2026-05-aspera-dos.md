---
title: 'CVE-2026-8180: IBM Aspera High-Speed Transfer Denial of Service'
slug: 2026-05-aspera-dos
description: IBM Aspera High-Speed Transfer Endpoint and Server versions 3.7.4 through 4.4.7 Fix Pack 1 are vulnerable to a denial-of-service (DoS) attack where an unauthenticated user can crash the asperahttpd service.
date: "2026-05-27T14:20:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - cve
vendors:
  - IBM
products:
  - Aspera High-Speed Transfer Endpoint
  - Aspera High-Speed Transfer Endpoint 3.7.4
  - Aspera High-Speed Transfer Endpoint 3.7.5
  - Aspera High-Speed Transfer Endpoint 3.7.6
  - Aspera High-Speed Transfer Endpoint 3.7.7
  - Aspera High-Speed Transfer Endpoint 3.7.8
  - Aspera High-Speed Transfer Endpoint 3.7.9
  - Aspera High-Speed Transfer Endpoint 3.7.10
  - Aspera High-Speed Transfer Endpoint 3.7.11
  - Aspera High-Speed Transfer Endpoint 3.7.4 through 4.4.7 Fix Pack 1
  - Aspera High-Speed Transfer Server 3.7.4
  - Aspera High-Speed Transfer Server 3.7.5
  - Aspera High-Speed Transfer Server 3.7.6
  - Aspera High-Speed Transfer Server 3.7.7
  - Aspera High-Speed Transfer Server 3.7.8
  - Aspera High-Speed Transfer Server 3.7.9
  - Aspera High-Speed Transfer Server 3.7.10
  - Aspera High-Speed Transfer Server 3.7.11
  - Aspera High-Speed Transfer Server 3.7.4 through 4.4.7 Fix Pack 1
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-8180
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8180
  - https://www.ibm.com/support/pages/node/7273615
rules:
  - title: Detect Asperahttpd Service Crash
    description: Detects crashes of the asperahttpd service, potentially indicating exploitation of CVE-2026-8180
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - application
      - linux
  - title: Detect Asperahttpd High CPU Usage
    description: Detects high CPU usage by the asperahttpd process which may indicate a denial-of-service attack.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_usage
      - linux
rules_count: 2
---

IBM Aspera High-Speed Transfer Endpoint and Server are affected by a denial-of-service vulnerability. Specifically, versions 3.7.4 through 4.4.7 Fix Pack 1 of both the Endpoint and Server products, along with the general Aspera High-Speed Transfer Endpoint, are susceptible to this flaw. The vulnerability lies within the `asperahttpd` component, where an unauthenticated user can trigger a crash of the service. This can disrupt file transfer operations and potentially impact overall system availability. The CVE ID associated with this vulnerability is CVE-2026-8180.

## Attack Chain

1.  An unauthenticated attacker sends a crafted request to the `asperahttpd` service.
2.  The crafted request triggers a null pointer dereference within the `asperahttpd` component (CWE-476).
3.  The null pointer dereference causes the `asperahttpd` service to crash.
4.  The crash disrupts normal operation of the Aspera High-Speed Transfer Endpoint or Server.
5.  Users are unable to initiate or complete file transfers.
6.  Repeated exploitation leads to sustained denial of service.

## Impact

Successful exploitation of CVE-2026-8180 results in a denial of service, impacting the availability of the Aspera High-Speed Transfer Endpoint and Server. This can disrupt critical file transfer workflows, potentially leading to data delivery delays and operational downtime. The number of affected systems depends on the number of deployments running the vulnerable versions.

## Recommendation

*   Upgrade IBM Aspera High-Speed Transfer Endpoint and Server to a version beyond 4.4.7 Fix Pack 1 to remediate CVE-2026-8180, as recommended by the vendor advisory (https://www.ibm.com/support/pages/node/7273615).
*   Deploy the Sigma rule "Detect Asperahttpd Service Crash" to monitor for crashes related to potential exploitation attempts.
*   Monitor network traffic for anomalous requests targeting the `asperahttpd` service to identify potential exploitation attempts.
