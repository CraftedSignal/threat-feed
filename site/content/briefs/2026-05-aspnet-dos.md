---
title: CVE-2026-42899 - ASP.NET Core Infinite Loop Denial of Service
slug: 2026-05-aspnet-dos
description: CVE-2026-42899 describes an infinite loop vulnerability in ASP.NET Core that allows an unauthorized attacker to perform a denial of service attack over a network.
date: "2026-05-12T18:54:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - asp.net
  - CVE-2026-42899
vendors:
  - Microsoft
products:
  - ASP.NET Core
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-42899
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42899
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42899
rules:
  - title: Detects CVE-2026-42899 Exploitation Attempt — High CPU Usage by ASP.NET Core
    description: Detects CVE-2026-42899 exploitation — Monitors for sustained high CPU usage by the ASP.NET Core process, which could indicate an infinite loop.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2026-42899 Exploitation Attempt - Excessive Requests to Specific Endpoint
    description: Detects CVE-2026-42899 exploitation — Tracks the number of requests to a specific endpoint, triggering an alert if a threshold is exceeded, which could indicate an attempt to trigger an infinite loop.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-42899 details a denial-of-service vulnerability affecting ASP.NET Core. The vulnerability stems from a loop with an unreachable exit condition, effectively creating an infinite loop. An unauthorized attacker can exploit this flaw to exhaust server resources, leading to a denial of service for legitimate users. Microsoft has acknowledged this vulnerability and assigned it a CVSS v3.1 score of 7.5, highlighting the potential impact. Exploitation occurs over a network, requiring no user interaction or privileges. This vulnerability poses a significant risk to web applications built on ASP.NET Core, potentially disrupting services and impacting availability. Defenders should prioritize patching and consider implementing mitigations to prevent exploitation.

## Attack Chain

1.  The attacker sends a specially crafted HTTP request to an ASP.NET Core endpoint.
2.  The request triggers the vulnerable code path containing the infinite loop.
3.  The application enters an infinite loop, consuming CPU resources.
4.  As the CPU usage increases, the server's performance degrades.
5.  The server becomes unresponsive to legitimate user requests.
6.  The attacker continues to send malicious requests to maintain the denial of service.
7.  The server eventually exhausts its resources (CPU, memory).

## Impact

Successful exploitation of CVE-2026-42899 leads to a denial-of-service condition on ASP.NET Core applications. This can result in website unavailability, disrupted services, and potential financial losses due to downtime. The vulnerability can be exploited remotely without authentication, making it easily accessible to attackers. The impact is significant, as affected applications become unusable until the issue is resolved. The high CVSS score of 7.5 reflects the severity of the potential disruption and the relative ease of exploitation.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-42899 on all ASP.NET Core servers (reference: Microsoft Security Update Guide).
*   Deploy the Sigma rule provided below to detect potential exploitation attempts by monitoring for abnormal CPU utilization patterns (reference: Sigma rule).
*   Monitor web server logs for suspicious requests that might be triggering the infinite loop (reference: webserver logs).
