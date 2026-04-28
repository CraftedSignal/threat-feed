---
title: Anviz CrossChex Standard TDS7 PreLogin Encryption Vulnerability
slug: 2026-04-anviz-crosschex-vuln
description: Anviz CrossChex Standard is vulnerable to unauthorized database access due to the manipulation of TDS7 PreLogin, which disables encryption, leading to plaintext transmission of database credentials.
date: "2026-04-18T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-32650
  - credential-access
  - database
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-32650
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32650
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-106-03.json
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-106-03
iocs:
  - type: email
    value: cert@us-cert.gov
ioc_counts:
  email: 1
rules:
  - title: Detect Unencrypted TDS7 PreLogin Connection
    description: Detects network connections to the TDS7 PreLogin port without encryption, indicating potential exploitation of CVE-2026-32650.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.006
    data_sources:
      - network_connection
      - windows
  - title: Detect Potential Database Access from Unexpected Process
    description: Detects processes other than the legitimate Anviz CrossChex application accessing the database.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Anviz CrossChex Standard is susceptible to a critical vulnerability (CVE-2026-32650) where an attacker can manipulate the TDS7 PreLogin process. By exploiting this flaw, an attacker can disable encryption mechanisms, causing sensitive database credentials to be transmitted in plaintext. This exposure enables unauthorized access to the underlying database, potentially leading to data breaches, modification of records, or other malicious activities. The vulnerability was disclosed in April 2026 and poses a significant risk to organizations utilizing the affected Anviz CrossChex Standard software. The vulnerability exists because the application allows for a downgrade to a less secure algorithm during negotiation.

## Attack Chain

1.  The attacker identifies an Anviz CrossChex Standard instance exposed to network access.
2.  The attacker initiates a connection to the TDS7 PreLogin port.
3.  The attacker crafts a malicious TDS7 PreLogin packet to negotiate a connection without encryption.
4.  The CrossChex Standard software, due to the vulnerability, accepts the unencrypted connection.
5.  The software transmits database credentials in plaintext over the unencrypted channel.
6.  The attacker intercepts the plaintext database credentials.
7.  The attacker uses the obtained credentials to authenticate directly to the database server.
8.  The attacker gains unauthorized access to the CrossChex Standard database, enabling them to read, modify, or delete sensitive data.

## Impact

Successful exploitation of CVE-2026-32650 allows unauthorized access to the Anviz CrossChex Standard database. This can lead to the exposure of sensitive employee data, including personal information and access control details. Depending on the database permissions, an attacker could also modify time and attendance records, manipulate user accounts, or even compromise the entire physical access control system managed by CrossChex Standard. The impact could range from privacy violations to significant security breaches affecting physical premises.

## Recommendation

*   Apply available patches or updates for Anviz CrossChex Standard as provided by the vendor to remediate CVE-2026-32650.
*   Monitor network traffic for connections to the TDS7 PreLogin port that do not negotiate encryption using the provided network connection Sigma rule.
*   Restrict network access to the TDS7 PreLogin port only to trusted hosts and networks using firewall rules to mitigate the risk of unauthorized access.
*   Enable logging on the database server and monitor for successful logins from unusual IP addresses or accounts after applying the network connection Sigma rule.
