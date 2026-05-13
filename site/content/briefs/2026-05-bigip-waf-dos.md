---
title: BIG-IP Advanced WAF/ASM Denial-of-Service Vulnerability (CVE-2026-40060)
slug: 2026-05-bigip-waf-dos
description: CVE-2026-40060 describes a vulnerability in F5 BIG-IP Advanced WAF and ASM security policies where undisclosed requests can cause the `bd` process to terminate, leading to a denial-of-service condition.
date: "2026-05-13T16:21:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - web application firewall
  - F5
  - CVE-2026-40060
vendors:
  - F5 Networks
products:
  - BIG-IP Advanced WAF
  - BIG-IP ASM
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-40060
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40060
  - https://my.f5.com/manage/s/article/K000160727
rules:
  - title: Detect BIG-IP bd Process Crash
    description: Detects potential exploitation of CVE-2026-40060 by monitoring for unexpected `bd` process termination events.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect BIG-IP WAF/ASM HTTP Requests Leading to bd Process Termination
    description: Detects suspicious HTTP requests potentially leading to CVE-2026-40060 exploitation by monitoring for specific URI patterns.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-40060 is a denial-of-service vulnerability affecting F5 BIG-IP Advanced Web Application Firewall (WAF) and Application Security Manager (ASM) modules. When a BIG-IP virtual server is configured with an Advanced WAF or ASM security policy, specially crafted, undisclosed requests can trigger the termination of the `bd` process. This can lead to a denial-of-service condition, impacting the availability of web applications protected by the affected BIG-IP system. The vulnerability was reported to F5 Networks and assigned a CVSS v3.1 base score of 7.5 (High). Software versions that have reached End of Technical Support (EoTS) are not evaluated.

## Attack Chain

1. An attacker identifies a vulnerable BIG-IP system with an Advanced WAF or ASM security policy enabled on a virtual server.
2. The attacker crafts a series of undisclosed HTTP requests.
3. The attacker sends the malicious requests to the targeted virtual server.
4. The BIG-IP system processes the requests through the configured WAF/ASM security policy.
5. The crafted requests trigger a fault or unhandled exception within the `bd` process.
6. The `bd` process terminates unexpectedly as a result of the crafted malicious requests.
7. The termination of the `bd` process disrupts the normal operation of the BIG-IP system.
8. Web applications protected by the affected virtual server become unavailable, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-40060 results in a denial-of-service (DoS) condition, rendering web applications protected by the vulnerable BIG-IP system unavailable. The impact is high in terms of availability, as legitimate users are unable to access the affected services. This can lead to business disruption, reputational damage, and potential financial losses for organizations relying on the affected BIG-IP systems. The specific number of victims and sectors targeted will vary depending on the prevalence of the vulnerable configuration.

## Recommendation

*   Refer to F5's advisory K000160727 for detailed information and mitigation steps.
*   Apply the necessary updates or workarounds provided by F5 Networks to address CVE-2026-40060 on vulnerable BIG-IP Advanced WAF and ASM deployments.
*   Monitor web server logs for unusual traffic patterns or anomalies that may indicate exploitation attempts, and deploy the Sigma rule detecting `bd` process crashes to identify potential attacks.
*   Implement rate limiting and traffic filtering mechanisms to mitigate the impact of potential denial-of-service attacks.
