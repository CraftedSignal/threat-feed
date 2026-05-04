---
title: MariaDB Vulnerability Allows Denial of Service and Potential Code Execution
slug: 2024-01-mariadb-dos
description: A remote, authenticated attacker can exploit a vulnerability in MariaDB to perform a denial of service attack and potentially execute arbitrary program code.
date: "2026-05-04T09:34:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mariadb
  - denial-of-service
  - code-execution
vendors:
  - MariaDB
products:
  - MariaDB
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0815
rules:
  - title: Detect Suspicious MariaDB Stored Procedure Execution
    description: Detects the execution of stored procedures in MariaDB that may be indicative of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - webserver
      - linux
  - title: Detect MariaDB Login Failures from Unusual Source IPs
    description: Detects MariaDB login failures originating from IP addresses not typically associated with legitimate access.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1110.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists in MariaDB that allows a remote, authenticated attacker to perform a denial of service attack and potentially execute arbitrary program code. This vulnerability could be exploited by an attacker who has already gained valid credentials to the MariaDB server. Successful exploitation leads to service disruption and potential compromise of the underlying system. Defenders should implement appropriate access controls and monitoring to detect and prevent unauthorized access and exploitation attempts. This vulnerability poses a significant risk to organizations relying on MariaDB for critical services.

## Attack Chain

1. The attacker obtains valid credentials for a MariaDB user, potentially through credential stuffing, phishing, or other means.
2. The attacker authenticates to the MariaDB server using the compromised credentials.
3. The attacker crafts a malicious SQL query or stored procedure designed to trigger the vulnerability.
4. The attacker executes the malicious query or stored procedure against the MariaDB server.
5. The vulnerability is triggered, leading to a denial of service condition, potentially crashing the MariaDB server process.
6. If the vulnerability allows code execution, the attacker injects malicious code into the MariaDB process.
7. The malicious code executes with the privileges of the MariaDB process.
8. The attacker gains further control of the system or performs other malicious activities.

## Impact

Successful exploitation of this vulnerability can lead to a denial of service, disrupting services relying on MariaDB. In the event of code execution, the attacker could potentially gain complete control of the system, leading to data exfiltration, data manipulation, or further compromise of the network. The number of affected organizations is potentially large, as MariaDB is a widely used database server.

## Recommendation

*   Implement strong password policies and multi-factor authentication to prevent credential compromise and unauthorized access to MariaDB servers.
*   Monitor MariaDB logs for suspicious activity, such as failed login attempts, unusual query patterns, or attempts to execute stored procedures from unexpected sources. Deploy the Sigma rule `DetectSuspiciousMariaDBStoredProcedureExecution` to detect the execution of potentially malicious stored procedures.
*   Regularly review and update access control lists to ensure that users only have the necessary privileges to perform their duties.
