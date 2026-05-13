---
title: VMware Tanzu Spring Framework Denial of Service Vulnerability
slug: 2026-05-vmware-tanzu-dos
description: An anonymous, remote attacker can exploit a vulnerability in VMware Tanzu Spring Framework to cause a denial of service.
date: "2026-05-13T08:15:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - spring-framework
  - vmware
vendors:
  - VMware
products:
  - Tanzu Spring Framework
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2024-3473
rules:
  - title: Detect Potential Denial of Service Attack Against Spring Framework
    description: Detects potential denial of service attacks targeting Spring Framework applications based on suspicious HTTP request patterns.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 1
---

VMware Tanzu Spring Framework is susceptible to a denial-of-service (DoS) vulnerability. This vulnerability allows an unauthenticated remote attacker to disrupt the availability of applications built on the framework. The specific details of the vulnerability are not disclosed in this advisory, but successful exploitation results in the disruption of service, impacting legitimate users and potentially causing financial loss due to downtime. Organizations using VMware Tanzu Spring Framework should prioritize detection and mitigation measures to prevent potential exploitation.

## Attack Chain

1.  Attacker identifies a vulnerable instance of VMware Tanzu Spring Framework exposed to the internet.
2.  Attacker crafts a malicious request specifically designed to trigger the vulnerability in the Spring Framework.
3.  The malicious request is sent to the targeted endpoint on the vulnerable Spring Framework application.
4.  The Spring Framework processes the malicious request, leading to excessive resource consumption or a crash.
5.  The affected Spring Framework application becomes unresponsive or crashes, denying service to legitimate users.
6.  The attacker repeats the process to maintain the denial-of-service condition, further disrupting the application's availability.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition, rendering VMware Tanzu Spring Framework applications unavailable. This can impact critical business operations, leading to financial losses, reputational damage, and disruption of services for end-users. The number of affected applications and the extent of the impact depend on the deployment size and criticality of the applications built on the vulnerable Spring Framework.

## Recommendation

*   Deploy the Sigma rule provided below to detect suspicious activity related to potential DoS attacks against Tanzu Spring Framework applications.
*   Monitor web server logs for unusual request patterns that may indicate exploitation attempts (reference webserver log source in the provided Sigma rule).
