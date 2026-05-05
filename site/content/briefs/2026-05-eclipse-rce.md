---
title: Eclipse Equinox OSGi Console Remote Code Execution Vulnerability
slug: 2026-05-eclipse-rce
description: Eclipse Equinox OSGi versions 3.8 through 3.18 contain a remote code execution vulnerability allowing unauthenticated attackers to execute arbitrary code via the console interface fork command, leading to a reverse shell.
date: "2026-05-05T12:16:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - vulnerability
  - eclipse
vendors:
  - Eclipse
products:
  - Equinox OSGi (3.8 through 3.18)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2023-54342
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54342
  - https://www.exploit-db.com/exploits/51878
  - https://www.vulncheck.com/advisories/eclipse-equinox-osgi-console-remote-code-execution
rules:
  - title: Detect Equinox OSGi Fork Command
    description: Detects the use of the 'fork' command in network connections to Eclipse Equinox OSGi consoles, indicative of CVE-2023-54342 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Equinox OSGi Console Connection
    description: Detects Telnet connections to port 23, a common port for Equinox OSGi consoles, which may indicate attempts to exploit CVE-2023-54342.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2023-54342 describes a critical remote code execution vulnerability affecting Eclipse Equinox OSGi versions 3.8 through 3.18. The vulnerability resides in the console interface and allows unauthenticated attackers to execute arbitrary code. This is achieved by exploiting the "fork" command functionality. Successful exploitation enables attackers to establish a telnet connection to the OSGi console, perform a telnet handshake, and subsequently send specially crafted "fork" commands. These commands can be leveraged to download and execute malicious Java code, ultimately establishing a reverse shell connection. This vulnerability poses a significant risk to systems running vulnerable versions of Eclipse Equinox OSGi.

## Attack Chain

1.  An unauthenticated attacker establishes a telnet connection to the target Eclipse Equinox OSGi console.
2.  The attacker performs the necessary telnet handshake to initiate communication with the console.
3.  The attacker sends a "fork" command to the OSGi console. This command is crafted to download a malicious Java payload from a remote server.
4.  The OSGi console executes the "fork" command, downloading the malicious Java payload.
5.  The downloaded Java payload is executed within the context of the OSGi console.
6.  The malicious Java code establishes a reverse shell connection back to the attacker's controlled server.
7.  The attacker gains remote access to the compromised system via the reverse shell.

## Impact

Successful exploitation of CVE-2023-54342 allows an unauthenticated attacker to achieve remote code execution on systems running vulnerable versions of Eclipse Equinox OSGi (3.8-3.18). This can lead to complete system compromise, data exfiltration, and denial-of-service conditions. The absence of authentication requirements significantly increases the risk of exploitation.

## Recommendation

*   Upgrade Eclipse Equinox OSGi to a version outside the vulnerable range (3.8 through 3.18) to remediate CVE-2023-54342.
*   Deploy the Sigma rule "Detect Equinox OSGi Fork Command" to identify exploitation attempts in network connection logs.
*   Monitor network connections originating from Equinox OSGi processes for suspicious outbound traffic, particularly connections to unusual or untrusted destinations.
