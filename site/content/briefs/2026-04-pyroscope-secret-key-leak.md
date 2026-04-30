---
title: Pyroscope Secret Key Exposure via Tencent COS Configuration (CVE-2025-41118)
slug: 2026-04-pyroscope-secret-key-leak
description: CVE-2025-41118 allows an attacker with direct access to the Pyroscope API, when configured with Tencent COS, to extract the secret_key configuration value, potentially leading to unauthorized access to the cloud storage backend.
date: "2026-04-16T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - pyroscope
  - tencent-cos
  - secret-key-exposure
  - cve-2025-41118
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-41118
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-41118
rules:
  - title: Detect Pyroscope Configuration Request
    description: Detects suspicious requests to the Pyroscope API that may attempt to access sensitive configuration data.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1592.004
    data_sources:
      - webserver
      - linux
  - title: Detect Pyroscope API Access from External IPs
    description: Detects access to the Pyroscope API from IP addresses outside the expected internal network range.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Pyroscope is an open-source continuous profiling database that supports various storage backends, including Tencent Cloud Object Storage (COS). A vulnerability, identified as CVE-2025-41118, exists where an attacker with direct access to the Pyroscope API can extract the `secret_key` configuration value when Tencent COS is used as the storage backend. This vulnerability poses a significant risk as the exposed secret key could allow unauthorized access to the Tencent COS storage, potentially leading to data breaches or other malicious activities. The vulnerability has been patched in versions 1.15.2 and above, 1.16.1 and above, and all versions of 1.17.x. It is strongly recommended to limit public internet exposure of Pyroscope API instances.

## Attack Chain

1.  Attacker gains network access to the Pyroscope API endpoint, either through public exposure or internal network penetration.
2.  Attacker sends a crafted HTTP request to the Pyroscope API endpoint designed to expose configuration details. The specific API endpoint and parameters are not detailed in the source but are assumed to exist for configuration management.
3.  The vulnerable Pyroscope API processes the request without proper authorization or input validation.
4.  The API retrieves the Tencent COS storage configuration, including the `secret_key`.
5.  The `secret_key` is inadvertently included in the API response to the attacker.
6.  Attacker extracts the `secret_key` from the API response.
7.  Attacker uses the compromised `secret_key` to authenticate to Tencent COS.
8.  Attacker gains unauthorized access to data stored in the Tencent COS bucket associated with the compromised `secret_key`, potentially leading to data exfiltration, modification, or deletion.

## Impact

Successful exploitation of CVE-2025-41118 grants an attacker unauthorized access to the Tencent COS storage backend used by Pyroscope. This access allows the attacker to read, modify, or delete data stored in the cloud storage. The impact depends on the sensitivity of the data stored in Tencent COS. In a worst-case scenario, a complete data breach and service disruption are possible. The number of affected Pyroscope installations is currently unknown.

## Recommendation

*   Upgrade Pyroscope instances to the patched versions: 1.15.2+, 1.16.1+, or any 1.17.x version to remediate CVE-2025-41118.
*   Implement network access controls to restrict access to the Pyroscope API to trusted users or internal systems, mitigating initial access, as suggested in the overview.
*   Deploy the Sigma rule `Detect Pyroscope Configuration Request` to identify potential attempts to access sensitive configuration data via the API.
*   Regularly review and audit the configuration of Pyroscope and its storage backends (Tencent COS) to ensure proper security measures are in place.
