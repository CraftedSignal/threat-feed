---
title: Core FTP/SFTP Server 1.2 Buffer Overflow Vulnerability (CVE-2019-25654)
slug: 2024-01-coreftp-buffer-overflow
description: Core FTP/SFTP Server 1.2 is vulnerable to a buffer overflow, allowing attackers to crash the service by providing an excessively long string in the User domain field.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer overflow
  - denial of service
  - cve-2019-25654
  - core ftp
  - sftp
  - windows
vendors:
  - Core FTP
products:
  - Core FTP/SFTP Server
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25654
rules:
  - title: Core FTP/SFTP Server Buffer Overflow Attempt
    description: Detects attempts to exploit CVE-2019-25654 by monitoring process creation for unusually long command-line arguments potentially related to the Core FTP configuration.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - process_creation
      - windows
  - title: Core FTP Service Crash Event
    description: Detects crash events associated with Core FTP service that may indicate CVE-2019-25654 exploitation
    platform: sigma
    severity: critical
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - application
      - windows
rules_count: 2
---

Core FTP/SFTP Server version 1.2 is susceptible to a buffer overflow vulnerability, identified as CVE-2019-25654. This vulnerability allows a remote attacker to crash the FTP service by sending an overly long string to the User domain field. The attack involves pasting a malicious payload containing approximately 7000 bytes of data into the domain configuration, triggering a buffer overflow condition within the application. Successful exploitation of this vulnerability leads to a denial-of-service condition, impacting the availability of the FTP service for legitimate users. This vulnerability was reported in 2019 and continues to pose a risk to unpatched installations.

## Attack Chain

1. Attacker identifies a vulnerable Core FTP/SFTP Server 1.2 instance.
2. Attacker gains access to the domain configuration settings of the Core FTP/SFTP server. This could be through exposed admin panel, or other means.
3. Attacker crafts a malicious payload consisting of an excessively long string (approximately 7000 bytes).
4. Attacker pastes the malicious payload into the User domain field within the server's configuration settings.
5. The server attempts to process the oversized input without proper bounds checking.
6. A buffer overflow occurs, overwriting adjacent memory regions.
7. The application's execution is disrupted due to corrupted memory.
8. The Core FTP/SFTP server crashes, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2019-25654 results in a denial-of-service condition, rendering the Core FTP/SFTP Server 1.2 unavailable. This can disrupt file transfer operations, potentially impacting business processes that rely on the server. While the provided source does not detail specific victim counts or sectors targeted, the vulnerability could affect any organization utilizing the affected version of Core FTP/SFTP Server. The severity is considered high due to the ease of exploitation and the direct impact on service availability.

## Recommendation

*   Upgrade Core FTP/SFTP Server to a patched version that addresses CVE-2019-25654 to remediate the vulnerability.
*   Implement input validation on the User domain field within the server configuration to prevent excessively long strings from being processed. Enable process creation logging and deploy the provided Sigma rule to detect potential exploitation attempts targeting CVE-2019-25654.
