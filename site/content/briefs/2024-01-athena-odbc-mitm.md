---
title: Amazon Athena ODBC Driver Man-in-the-Middle Vulnerability
slug: 2024-01-athena-odbc-mitm
description: A man-in-the-middle vulnerability exists in Amazon Athena ODBC driver versions prior to 2.1.0.0 due to improper certificate validation, potentially allowing attackers to intercept authentication credentials when connecting to external identity providers.
date: "2026-04-03T21:17:12Z"
type: advisory
types:
  - advisory
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

A man-in-the-middle (MitM) vulnerability has been identified in the Amazon Athena ODBC driver. Specifically, versions prior to 2.1.0.0 exhibit improper certificate validation within the identity provider connection components. This flaw allows a threat actor positioned in the network to intercept authentication credentials when the driver attempts to connect to external identity providers. This vulnerability, identified as CVE-2026-35560, poses a significant risk to organizations utilizing affected versions of the Athena ODBC driver with external identity providers. The lack of proper certificate validation can lead to credential compromise and subsequent unauthorized access to sensitive data within Athena. This does not affect connections directly to Athena.

## Attack Chain

1.  The attacker positions themselves in a privileged network location between the user's machine and the external identity provider.
2.  The user attempts to establish a connection to Amazon Athena using the vulnerable ODBC driver version (prior to 2.1.0.0). The connection is configured to use an external identity provider for authentication.
3.  The ODBC driver initiates a connection to the configured external identity provider.
4.  The attacker intercepts the network traffic between the ODBC driver and the identity provider.
5.  Due to the lack of proper certificate validation in the vulnerable ODBC driver, the attacker can present a fraudulent certificate to the driver without triggering an error.
6.  The ODBC driver, trusting the fraudulent certificate, proceeds with the authentication process and transmits the user's credentials to the attacker-controlled server.
7.  The attacker captures the user's authentication credentials (e.g., username and password or an access token).
8.  The attacker uses the stolen credentials to authenticate to the external identity provider or directly to resources protected by those credentials, potentially gaining unauthorized access to sensitive data within Amazon Athena or other connected services.

## Impact

Successful exploitation of this vulnerability allows a man-in-the-middle attacker to intercept authentication credentials used to connect to external identity providers. This could lead to unauthorized access to an organization's Amazon Athena data and other resources protected by the compromised credentials. The severity of the impact depends on the privileges associated with the compromised user account. If successful, the attacker could potentially read, modify, or delete sensitive data stored in Athena, leading to data breaches, financial losses, and reputational damage. The number of potential victims is directly proportional to the number of organizations using affected versions of the Athena ODBC driver with external identity providers.

## Recommendation

*   Upgrade the Amazon Athena ODBC driver to version 2.1.0.0 or later to remediate the improper certificate validation vulnerability as documented in CVE-2026-35560.
*   Monitor network traffic for unexpected connections to external identity providers from machines running the Athena ODBC driver. Use network connection logs to identify suspicious activity.
*   Implement network segmentation to limit the potential impact of a successful man-in-the-middle attack, reducing the attacker's ability to intercept traffic.
