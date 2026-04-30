---
title: Amazon Athena ODBC Driver Command Injection Vulnerability (CVE-2026-35558)
slug: 2026-04-athena-odbc-injection
description: A command injection vulnerability (CVE-2026-35558) exists in the Amazon Athena ODBC driver before 2.1.0.0 due to improper neutralization of special elements in connection parameters, potentially leading to arbitrary code execution or authentication redirection.
date: "2026-04-03T21:17:11Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - command injection
  - cve-2026-35558
  - athena
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35558
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35558
  - https://aws.amazon.com/security/security-bulletins/2026-013-aws/
  - https://docs.aws.amazon.com/athena/latest/ug/odbc-v2-driver-release-notes.html
rules:
  - title: Detect Suspicious Process Creation from Athena ODBC Driver (Windows)
    description: Detects suspicious process creation events where the parent process is the Amazon Athena ODBC driver executable, potentially indicating command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Athena ODBC Driver Network Connection
    description: Detects suspicious network connections initiated by the Amazon Athena ODBC driver executable to unusual destinations, potentially indicating command and control activity after successful command injection.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Amazon Athena ODBC driver versions prior to 2.1.0.0 are susceptible to a command injection vulnerability, identified as CVE-2026-35558. This flaw arises from the driver's failure to properly neutralize special elements within connection parameters during the authentication process. A remote attacker could exploit this vulnerability by crafting malicious connection strings that, when processed by the vulnerable driver, allow for the execution of arbitrary code on the system or redirection of the authentication flow. The vulnerability was disclosed on April 3, 2026. Organizations utilizing the affected Amazon Athena ODBC driver versions on Windows, Linux, and macOS systems are at risk. Upgrade to version 2.1.0.0 to mitigate the risk.

## Attack Chain

1. An attacker identifies a system using a vulnerable version of the Amazon Athena ODBC driver (prior to 2.1.0.0).
2. The attacker crafts a malicious ODBC connection string containing special characters or commands designed to be executed by the underlying operating system.
3. A user or application attempts to connect to Amazon Athena using the crafted connection string.
4. The vulnerable Amazon Athena ODBC driver processes the connection string, failing to properly neutralize the special elements.
5. The injected commands are executed by the operating system, potentially allowing the attacker to gain control of the system. This is due to the driver calling system functions to process the parameters without proper sanitization.
6. The attacker could install malware, exfiltrate sensitive data, or pivot to other systems on the network.
7. Alternatively, the attacker can redirect the authentication flow to a malicious server.
8. The attacker gains unauthorized access to the Athena database or the system.

## Impact

Successful exploitation of CVE-2026-35558 allows an attacker to execute arbitrary code on the affected system with the privileges of the user running the application using the ODBC driver. This can lead to complete system compromise, including data theft, system corruption, or use of the compromised system as a foothold for further attacks within the organization's network. While specific victim numbers are unknown, any system using a vulnerable version of the Amazon Athena ODBC driver is at risk. Sectors impacted depend on which organizations use Athena and the vulnerable ODBC driver.

## Recommendation

*   Immediately upgrade the Amazon Athena ODBC driver to version 2.1.0.0 or later on all affected systems (Windows, Linux, macOS) to remediate CVE-2026-35558, as recommended by Amazon in their security bulletin.
*   Implement strict input validation and sanitization for all connection parameters passed to the Amazon Athena ODBC driver to prevent exploitation of command injection vulnerabilities, mitigating the risk even if an older driver version is temporarily in use.
*   Enable process creation logging with command line arguments and monitor for unusual processes spawned by the Athena ODBC driver executable (e.g., `AmazonAthenaODBC.exe` on Windows) to detect potential command injection attempts.
