---
title: F5 BIG-IP APM Undisclosed Traffic Denial-of-Service Vulnerability (CVE-2026-40067)
slug: 2026-05-f5-big-ip-apm-dos
description: A vulnerability exists in F5 BIG-IP APM where, when an APM access policy is configured on a virtual server, undisclosed network traffic can cause the apmd process to terminate, resulting in a denial of service (CVE-2026-40067).
date: "2026-05-13T16:22:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - cve-2026-40067
  - f5
vendors:
  - F5 Networks
products:
  - BIG-IP APM
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-40067
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40067
  - https://my.f5.com/manage/s/article/K000161056
rules:
  - title: Detect BIG-IP APM apmd Process Crash
    description: Detects unexpected termination of the apmd process, potentially indicating exploitation of CVE-2026-40067.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect BIG-IP APM apmd Process Crash (Syslog)
    description: Detects unexpected termination of the apmd process, potentially indicating exploitation of CVE-2026-40067, from Syslog events.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - system
      - linux
rules_count: 2
---

A denial-of-service vulnerability exists in F5 BIG-IP Access Policy Manager (APM). When an APM access policy is configured on a virtual server, sending undisclosed traffic can trigger a termination of the `apmd` process. This vulnerability is identified as CVE-2026-40067 and has a CVSS v3.1 base score of 7.5. Successful exploitation results in a denial of service, impacting the availability of the affected virtual server. Software versions that have reached End of Technical Support (EoTS) are not evaluated. Defenders should apply relevant patches or mitigations from F5 Networks.

## Attack Chain

Due to the limited information available, a precise attack chain cannot be defined. However, a plausible attack chain involves the following general steps:

1. An attacker identifies a BIG-IP virtual server with an active APM access policy.
2. The attacker crafts malicious network traffic. Details of the traffic are undisclosed in the vulnerability report.
3. The attacker sends the crafted traffic to the virtual server.
4. The APM processes the traffic via the `apmd` process.
5. The vulnerability within the `apmd` process is triggered due to the malicious traffic.
6. The `apmd` process terminates unexpectedly.
7. The virtual server becomes unavailable due to the termination of the `apmd` process.
8. Legitimate users are unable to access resources protected by the APM access policy.

## Impact

Successful exploitation of CVE-2026-40067 results in a denial-of-service condition on the targeted BIG-IP virtual server. This means legitimate users will be unable to access applications and services protected by the APM access policy. The NVD entry for this CVE lists a CVSS v3.1 base score of 7.5, indicating a high impact on availability. The number of affected organizations will depend on the prevalence of vulnerable BIG-IP APM configurations.

## Recommendation

*   Review and apply the mitigations or patches provided by F5 Networks in their security advisory K000161056 to address CVE-2026-40067.
*   Monitor network traffic for anomalies that may indicate exploitation attempts targeting BIG-IP APM (consider deploying generic DoS rules as a temporary measure).
*   Implement the Sigma rule `Detect BIG-IP APM apmd Process Crash` to identify unexpected terminations of the `apmd` process, which could signal exploitation of CVE-2026-40067.
