---
title: Logback Denial of Service Vulnerability
slug: 2024-05-logback-dos
description: A remote, anonymous attacker can exploit a vulnerability in Logback to perform a denial-of-service (DoS) attack.
date: "2024-05-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - logback
  - java
products:
  - Logback
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1498
    technique_name: Internal Defacement
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1496
    technique_name: Impair Resources
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2023-3050
rules:
  - title: Detect High Request Rate from Single IP - Possible DoS Attempt
    description: Detects a high number of requests originating from a single IP address within a short timeframe, which could indicate a denial-of-service attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple Failed Login Attempts from Single IP
    description: Detects multiple failed login attempts from the same IP within a defined timeframe, which can indicate brute-force or DoS attacks.
    platform: sigma
    severity: medium
    tactics:
      - resource_hijacking
    techniques:
      - T1110
      - T1496
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists in Logback that allows a remote, anonymous attacker to potentially conduct a denial-of-service attack. While the specific versions affected or the technical details of the vulnerability are not provided in the source, the generic nature of Logback's logging functionality implies a wide potential scope. Logback is a widely used logging framework for Java applications. Therefore, successful exploitation could lead to application downtime and resource exhaustion. Defenders should investigate their Logback deployments and apply relevant patches as they become available.

## Attack Chain

1.  The attacker identifies a vulnerable application using Logback. This could involve reconnaissance to determine the logging framework in use.
2.  The attacker crafts a malicious request or input designed to trigger excessive logging or resource consumption within the Logback framework.
3.  The attacker sends the crafted request to the vulnerable application. This could be via HTTP, network socket, or any other interface the application exposes.
4.  Logback processes the malicious input, potentially leading to excessive memory allocation or CPU usage as it attempts to log the data.
5.  The vulnerable application becomes unresponsive due to the resource exhaustion caused by Logback's excessive logging activity.
6.  The attacker repeats steps 3-5 to maintain the denial-of-service condition, preventing legitimate users from accessing the application.

## Impact

Successful exploitation of this Logback vulnerability results in a denial-of-service condition. The lack of specifics prevents accurate assessment of damage or victim count. Organizations using Logback could experience application downtime, leading to business disruption and potential data loss. The impact is dependent on the criticality of the affected applications.

## Recommendation

*   Monitor web server logs for unusual patterns indicative of denial-of-service attempts, specifically focusing on requests that might trigger excessive logging using the `webserver` category and `linux` or `windows` product in your SIEM.
*   Deploy the Sigma rule detecting high request rates from single IPs to identify potential DoS attempts against web applications using Logback.
*   Investigate and patch any identified Logback instances as updates become available from the vendor.
