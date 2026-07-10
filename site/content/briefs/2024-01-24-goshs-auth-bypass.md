---
title: goshs SimpleHTTPServer SFTP Authentication Bypass Vulnerability (CVE-2026-40884)
slug: 2024-01-24-goshs-auth-bypass
description: goshs SimpleHTTPServer prior to version 2.0.0-beta.6 contains an SFTP authentication bypass vulnerability that allows unauthenticated network attackers to access files when the server is started with specific configuration parameters.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - sftp
  - vulnerability
  - network
vendors:
  - goshs
products:
  - SimpleHTTPServer
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40884
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40884
rules:
  - title: Detect Suspicious SFTP Connection
    description: Detects suspicious SFTP connections from unusual locations.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect goshs Process with Vulnerable Configuration
    description: Detects goshs processes running with the vulnerable '-b ":pass"' configuration.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The goshs SimpleHTTPServer, a utility written in Go, is susceptible to an SFTP authentication bypass vulnerability (CVE-2026-40884) in versions prior to 2.0.0-beta.6. This flaw arises when the server is launched using the `-b ':pass'` argument in conjunction with the `-sftp` flag. This specific configuration prevents the application from properly initializing an SFTP password handler. Consequently, a remote, unauthenticated attacker can establish a connection to the SFTP service and gain unauthorized access to files stored on the server. This vulnerability poses a significant risk to data confidentiality and integrity. Organizations using affected versions of goshs should upgrade to version 2.0.0-beta.6 or later immediately.

## Attack Chain

1.  Attacker identifies a vulnerable goshs server running a version prior to 2.0.0-beta.6 with SFTP enabled using `-sftp` and the vulnerable authentication configuration `-b ':pass'`.
2.  Attacker establishes a network connection to the server's SFTP port (typically port 22, or a custom-configured port).
3.  The attacker initiates an SFTP connection without providing any username or password, exploiting the missing password handler.
4.  The vulnerable goshs server accepts the connection without authentication due to the configuration error.
5.  The attacker is granted access to the file system served by the goshs server via SFTP.
6.  The attacker navigates the file system, identifies sensitive files, and downloads them.
7.  Attacker exfiltrates the stolen data from the network.
8.  The attacker may use the compromised server as a pivot point for further attacks within the network.

## Impact

Successful exploitation of CVE-2026-40884 allows an unauthenticated attacker to access sensitive files stored on the vulnerable goshs server. The impact can range from information disclosure to complete compromise of the server and potential lateral movement within the network. Given the CVSS v3.1 base score of 9.8, this vulnerability represents a critical risk. The number of affected systems depends on the adoption rate of goshs and the specific configurations used.

## Recommendation

*   Upgrade goshs to version 2.0.0-beta.6 or later to patch CVE-2026-40884.
*   Review goshs server configurations and remove the vulnerable `-b ':pass'` configuration.
*   Monitor network connections to SFTP ports (default 22) for suspicious activity originating from unknown sources. Use the "Detect Suspicious SFTP Connection" Sigma rule provided below.
*   Implement network segmentation to limit the blast radius of a potential compromise.
