---
title: Eclipse Equinox OSGi Remote Code Execution Vulnerability (CVE-2023-54344)
slug: 2026-05-eclipse-rce
description: Eclipse Equinox OSGi 3.7.2 and earlier is vulnerable to remote code execution, allowing unauthenticated attackers to execute arbitrary commands by sending specially crafted payloads to the console interface, potentially leading to reverse shell creation.
date: "2026-05-05T12:16:16Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - rce
  - cve-2023-54344
  - eclipse
  - osgi
  - remote-code-execution
vendors:
  - Eclipse
products:
  - Equinox OSGi
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2023-54344
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54344
  - https://www.exploit-db.com/exploits/51879
  - https://www.vulncheck.com/advisories/eclipse-equinox-osgi-remote-code-execution-via-console
rules:
  - title: Detect Equinox OSGi Console Connections
    description: Detects network connections to the Equinox OSGi console port, which may indicate attempts to exploit CVE-2023-54344.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1021.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Equinox OSGi Base64 Encoded Commands
    description: Detects suspicious process command lines that contain base64 encoded data, which could indicate exploitation of CVE-2023-54344.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Eclipse Equinox OSGi 3.7.2 and earlier versions are susceptible to a critical remote code execution (RCE) vulnerability identified as CVE-2023-54344. This flaw allows unauthenticated attackers to remotely execute arbitrary commands by sending malicious payloads to the console interface of the affected systems. Attackers can exploit this vulnerability by connecting to the OSGi console port and injecting base64-encoded bash commands, typically wrapped within fork directives, which facilitates the execution of code and enables the establishment of reverse shell connections. This poses a significant threat as it can lead to complete system compromise without requiring any prior authentication.

## Attack Chain

1.  The attacker identifies a vulnerable Eclipse Equinox OSGi instance running version 3.7.2 or earlier.
2.  The attacker connects to the exposed OSGi console port (default port may vary).
3.  The attacker crafts a malicious payload containing a base64-encoded bash command.
4.  The payload is structured with "fork" directives to ensure proper execution within the OSGi environment.
5.  The attacker sends the crafted payload to the OSGi console interface via the network connection.
6.  The Equinox OSGi instance processes the payload, decoding and executing the embedded bash command.
7.  The executed command establishes a reverse shell connection back to the attacker's controlled system.
8.  The attacker gains remote access and can execute further commands, install malware, or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2023-54344 can lead to complete compromise of the affected Eclipse Equinox OSGi system. As an unauthenticated remote code execution vulnerability, it poses a critical risk to organizations using the vulnerable software. Attackers can gain full control over the system, potentially leading to data breaches, service disruption, or further lateral movement within the network. The absence of required authentication makes this vulnerability particularly dangerous.

## Recommendation

*   Upgrade Eclipse Equinox OSGi to a patched version greater than 3.7.2 to remediate CVE-2023-54344.
*   Implement network segmentation to restrict access to the OSGi console port from untrusted networks.
*   Deploy the Sigma rule "Detect Equinox OSGi Console Connections" to identify potential exploitation attempts via network connections.
*   Deploy the Sigma rule "Detect Equinox OSGi Base64 Encoded Commands" to detect suspicious base64 encoded commands indicative of exploitation.
