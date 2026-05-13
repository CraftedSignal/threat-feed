---
title: BIG-IP Configuration Utility LDAP Authentication Denial-of-Service (CVE-2026-39455)
slug: 2026-05-bigip-ldap-dos
description: CVE-2026-39455 describes a denial-of-service vulnerability in the BIG-IP Configuration utility when configured with LDAP authentication, where undisclosed traffic can cause the httpd process to exhaust file descriptors.
date: "2026-05-13T16:21:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - cve
vendors:
  - F5 Networks
products:
  - BIG-IP Configuration utility
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-39455
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39455
  - https://my.f5.com/manage/s/article/K000160874
rules:
  - title: Detect CVE-2026-39455 Exploitation Attempt - High File Descriptor Usage by httpd
    description: Detects CVE-2026-39455 exploitation attempt by monitoring for a high number of file descriptors opened by the httpd process, potentially indicating resource exhaustion.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect CVE-2026-39455 Exploitation Attempt - Unexpected LDAP Traffic Volume
    description: Detects CVE-2026-39455 exploitation attempt by monitoring for an unusual volume of LDAP traffic from the BIG-IP system.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-39455 affects the F5 BIG-IP Configuration utility. When the utility is configured to use Lightweight Directory Access Protocol (LDAP) for authentication, a specific type of undisclosed network traffic can trigger a denial-of-service condition. This occurs due to the httpd process exhausting available file descriptors, preventing legitimate users from accessing or managing the BIG-IP system. Exploitation requires the BIG-IP system to be configured for LDAP authentication. Software versions that have reached End of Technical Support (EoTS) are not evaluated.

## Attack Chain

1. The attacker sends undisclosed traffic to the BIG-IP Configuration utility.
2. The BIG-IP Configuration utility attempts to process the malicious traffic via the httpd process.
3. Due to the nature of the traffic and the LDAP configuration, the httpd process starts to open file descriptors.
4. The attacker continues to send the malicious traffic, causing the httpd process to rapidly consume available file descriptors.
5. The httpd process reaches the system's limit on open file descriptors.
6. Subsequent requests to the httpd process fail, as it cannot open new file descriptors to handle them.
7. Legitimate users are unable to access the BIG-IP Configuration utility, resulting in a denial-of-service.

## Impact

A successful attack exploiting CVE-2026-39455 results in a denial-of-service condition, rendering the BIG-IP Configuration utility inaccessible. Administrators are unable to manage or configure the BIG-IP system via the web interface, potentially impacting network operations and security. The severity is rated as High by F5 Networks with a CVSS v3.1 score of 7.5.

## Recommendation

*   Monitor web server logs for unusual patterns or high request rates targeting the BIG-IP Configuration utility to identify potential exploitation attempts.
*   Deploy the Sigma rule provided below to detect potential file descriptor exhaustion events related to the httpd process.
*   Refer to F5's advisory K000160874 for mitigation guidance and software updates.
