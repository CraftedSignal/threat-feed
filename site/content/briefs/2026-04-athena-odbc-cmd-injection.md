---
title: Amazon Athena ODBC Driver OS Command Injection Vulnerability (CVE-2026-5485)
slug: 2026-04-athena-odbc-cmd-injection
description: A critical OS command injection vulnerability (CVE-2026-5485) in the Amazon Athena ODBC driver before 2.0.5.1 for Linux allows local attackers to execute arbitrary code via specially crafted connection parameters.
date: "2026-04-04T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-5485
  - command injection
  - athena
  - odbc
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5485
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5485
  - https://aws.amazon.com/security/security-bulletins/2026-013-aws/
  - https://docs.aws.amazon.com/athena/latest/ug/odbc-v2-driver-release-notes.html
rules:
  - title: Detect Suspicious Athena ODBC Driver Process Creation
    description: Detects potential command injection attempts via suspicious command line arguments used with the Athena ODBC driver on Linux.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1203
    data_sources:
      - process_creation
      - linux
  - title: Detect Athena ODBC Driver Loading From Unusual Location
    description: Detects the Athena ODBC driver loading from a location outside the standard installation path.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1574.002
    data_sources:
      - image_load
      - linux
rules_count: 2
---

CVE-2026-5485 is an OS command injection vulnerability affecting the Amazon Athena ODBC driver before version 2.0.5.1 on Linux systems. The vulnerability resides in the browser-based authentication component of the driver. A local attacker can exploit this flaw by crafting malicious connection parameters that are then processed by the driver during a locally initiated connection attempt. Successful exploitation allows the attacker to execute arbitrary commands on the underlying system with the privileges of the user running the ODBC driver. This poses a significant risk to systems using vulnerable versions of the driver. The vulnerability was published on April 3, 2026.

## Attack Chain

1. An attacker gains local access to a Linux system with the vulnerable Amazon Athena ODBC driver installed (version before 2.0.5.1).
2. The attacker crafts specially crafted connection parameters designed to inject OS commands. This could involve manipulating fields expected by the driver to trigger command execution.
3. The attacker initiates a connection to Amazon Athena using the vulnerable ODBC driver and the crafted connection parameters.
4. The ODBC driver attempts to authenticate using the browser-based authentication component, loading the malicious connection parameters.
5. Due to the vulnerability, the crafted parameters are not properly sanitized, leading to OS command injection.
6. The injected OS commands are executed on the system with the privileges of the user running the ODBC driver.
7. The attacker can leverage the command execution to install malware, create new user accounts, or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2026-5485 allows an attacker to execute arbitrary commands on a vulnerable Linux system. The impact includes potential data theft, system compromise, and lateral movement within the network. Given the nature of command injection, the attacker has significant control over the compromised system, allowing for a wide range of malicious activities. Organizations using the affected Amazon Athena ODBC driver on Linux should prioritize patching to mitigate this risk.

## Recommendation

*   Upgrade the Amazon Athena ODBC driver to version 2.0.5.1 or later on all Linux systems to remediate CVE-2026-5485.
*   Monitor process creation events on Linux systems for unusual processes spawned by the ODBC driver using the Sigma rules provided below.
*   Implement strict access control policies on Linux systems to limit the ability of attackers to leverage local access to exploit the vulnerability.
*   Enable logging for ODBC driver activity and review logs for suspicious connection attempts.
*   Deploy the provided Sigma rule to detect potential exploitation attempts by monitoring for command line arguments indicative of command injection.
