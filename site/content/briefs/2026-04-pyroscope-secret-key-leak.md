---
title: Pyroscope Secret Key Exposure via Tencent COS Configuration (CVE-2025-41118)
slug: 2026-04-pyroscope-secret-key-leak
description: CVE-2025-41118 allows an attacker with direct access to the Pyroscope API, when configured with Tencent COS, to extract the secret_key configuration value, potentially leading to unauthorized access to the cloud storage backend.
date: "2026-04-16T12:00:00Z"
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

Pyroscope is an open-source continuous profiling database that supports various storage backends, including Tencent Cloud Object Storage (COS). A vulnerability, identified as CVE-2025-41118, exists where an attacker with direct access to the Pyroscope API can extract the `secret_key` configuration value when Tencent COS is used as the storage backend. This vulnerability poses a significant risk as the exposed secret key could allow unauthorized access to the Tencent COS storage, potentially…
