---
title: CAI Content Credentials Uncontrolled Resource Consumption Vulnerability (CVE-2026-34665)
slug: 2026-05-cai-resource-consumption
description: CAI Content Credentials versions 0.78.2, 0.7.0 and earlier are susceptible to an uncontrolled resource consumption vulnerability, potentially leading to a denial-of-service condition by exhausting system resources.
date: "2026-05-12T20:21:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - resource-consumption
  - cve
vendors:
  - Adobe Systems Incorporated
products:
  - CAI Content Credentials (<= 0.78.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-34665
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34665
  - https://helpx.adobe.com/security/products/content-authenticity-sdk/apsb26-53.html
rules:
  - title: Detects CVE-2026-34665 Exploitation — Excessive Memory Allocation
    description: Detects CVE-2026-34665 exploitation — monitors for a process exhibiting a significant increase in memory allocation, potentially indicating exploitation of the uncontrolled resource consumption vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2026-34665 Exploitation — High CPU Usage
    description: Detects CVE-2026-34665 exploitation — monitors for a process exhibiting high CPU utilization, potentially indicating exploitation of the uncontrolled resource consumption vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CAI Content Credentials, a software component developed by Adobe, is susceptible to an uncontrolled resource consumption vulnerability, as identified by CVE-2026-34665. This flaw exists in versions 0.78.2, 0.7.0, and prior releases. A remote, unauthenticated attacker could exploit this vulnerability to exhaust system resources, potentially leading to a denial-of-service (DoS) condition. Exploitation of the vulnerability does not require any user interaction, increasing the potential impact. The advisory was published May 12, 2026.

## Attack Chain

1.  An attacker sends a specially crafted request to an application utilizing CAI Content Credentials.
2.  The application processes the malicious request without proper resource management.
3.  The vulnerable component of CAI Content Credentials allocates excessive memory or CPU resources.
4.  The application's resource consumption steadily increases, impacting performance.
5.  Other legitimate requests are delayed or rejected due to resource contention.
6.  The application becomes unresponsive, leading to a denial-of-service condition.
7.  Administrators may observe high CPU utilization or memory exhaustion.

## Impact

Successful exploitation of CVE-2026-34665 can lead to a denial-of-service condition, impacting the availability of applications that rely on CAI Content Credentials. While the specific number of affected applications is currently unknown, organizations utilizing the vulnerable versions are at risk. A successful attack could disrupt critical business operations and damage the reputation of the organization.

## Recommendation

*   Upgrade CAI Content Credentials to a patched version beyond 0.78.2 to remediate CVE-2026-34665.
*   Deploy the Sigma rule provided to detect potential exploitation attempts of CVE-2026-34665 by monitoring for abnormal resource allocation patterns.
*   Implement rate limiting and resource quotas to mitigate the impact of potential resource exhaustion attacks.
*   Monitor system logs for resource exhaustion events and correlate them with network traffic patterns.
