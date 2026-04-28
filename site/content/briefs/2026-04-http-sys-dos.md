---
title: CVE-2026-33096 HTTP.sys Out-of-Bounds Read Denial-of-Service
slug: 2026-04-http-sys-dos
description: An unauthenticated, remote attacker can exploit an out-of-bounds read vulnerability (CVE-2026-33096) in Windows HTTP.sys to cause a denial-of-service condition.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-33096
  - denial-of-service
  - windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-33096
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33096
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33096
rules:
  - title: Detect Suspicious HTTP Request Length (Potential HTTP.sys DoS)
    description: Detects HTTP requests with unusually large Content-Length headers, potentially indicating a DoS attempt targeting HTTP.sys
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - windows
  - title: Detect High Volume of Requests to Web Server from Single IP
    description: Detects a high volume of requests to a web server from a single IP address within a short timeframe, potentially indicating a DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2026-33096 describes an out-of-bounds read vulnerability affecting the Windows HTTP.sys component. This vulnerability allows an unauthenticated attacker to remotely trigger a denial-of-service (DoS) condition on a vulnerable system. HTTP.sys is a core component of the Windows operating system that handles HTTP requests; therefore, a successful exploit can impact any service relying on HTTP.sys, including web servers and other network applications. The vulnerability was publicly disclosed on April 14, 2026. Due to the nature of the vulnerability and the wide use of HTTP.sys, it is critical to apply the patch released by Microsoft to prevent potential exploitation. The lack of specific exploit details does not diminish the severity, as the attack vector is simple: a specially crafted HTTP request sent over the network.

## Attack Chain

1.  The attacker identifies a target Windows server running a service that relies on HTTP.sys.
2.  The attacker crafts a malicious HTTP request specifically designed to trigger the out-of-bounds read vulnerability in HTTP.sys. This involves manipulating certain HTTP header values or request parameters.
3.  The attacker sends the crafted HTTP request to the targeted server over the network via port 80 or 443.
4.  HTTP.sys receives the malicious request and attempts to process it.
5.  Due to the vulnerability, HTTP.sys attempts to read data from a memory location outside of the allocated buffer, triggering an out-of-bounds read.
6.  The out-of-bounds read causes an exception or a crash within the HTTP.sys process.
7.  The HTTP.sys service becomes unresponsive, leading to a denial-of-service condition.
8.  Any services dependent on HTTP.sys, such as IIS web server, will also become unavailable, impacting legitimate users.

## Impact

Successful exploitation of CVE-2026-33096 leads to a denial-of-service condition, rendering affected Windows servers and services unavailable. The number of victims could potentially be very large, as HTTP.sys is a fundamental component in many Windows Server deployments. Affected sectors include any organization relying on Windows-based web services or applications using HTTP.sys. A successful attack disrupts normal operations, potentially causing financial losses, reputational damage, and business interruption. This vulnerability is particularly dangerous as it requires no authentication, making it easily exploitable.

## Recommendation

*   Apply the security update provided by Microsoft for CVE-2026-33096 to patch the vulnerability in HTTP.sys (reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33096).
*   Monitor web server logs for unusual or malformed HTTP requests that could be indicative of exploitation attempts targeting HTTP.sys (log source: webserver).
*   Implement the provided Sigma rule to detect suspicious HTTP requests potentially exploiting the vulnerability.
*   Enable network intrusion detection systems (IDS) to identify and block malicious HTTP traffic targeting port 80 or 443 (log source: firewall).
