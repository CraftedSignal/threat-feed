---
title: Amazon Athena ODBC Driver Man-in-the-Middle Vulnerability
slug: 2024-01-athena-odbc-mitm
description: A man-in-the-middle vulnerability exists in Amazon Athena ODBC driver versions prior to 2.1.0.0 due to improper certificate validation, potentially allowing attackers to intercept authentication credentials when connecting to external identity providers.
date: "2026-04-03T21:17:12Z"
severities:
  - high
tags:
  - cve-2026-35560
  - athena
  - odbc
  - man-in-the-middle
  - mitm
  - credential-theft
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Credentials Access
cves:
  - id: CVE-2026-35560
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35560
rules:
  - title: Detect Athena ODBC Driver Connecting to Uncommon Ports
    description: Detects Athena ODBC driver connecting to ports typically not associated with standard identity provider services, which might indicate a MITM attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1552.004
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Process Connecting to Athena ODBC Driver
    description: Detects processes unexpectedly connecting to AthenaODBC.exe, which could indicate a MitM attempt to inject malicious code or intercept communications.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1552.004
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A man-in-the-middle (MitM) vulnerability has been identified in the Amazon Athena ODBC driver. Specifically, versions prior to 2.1.0.0 exhibit improper certificate validation within the identity provider connection components. This flaw allows a threat actor positioned in the network to intercept authentication credentials when the driver attempts to connect to external identity providers. This vulnerability, identified as CVE-2026-35560, poses a significant risk to organizations utilizing…
