---
title: Casdoor 3.54.1 Arbitrary File Write via Path Traversal
slug: 2026-05-casdoor-path-traversal
description: Casdoor version 3.54.1 is vulnerable to a path traversal attack, allowing arbitrary file writes on the system, with a public exploit available.
date: "2026-05-27T13:10:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-write
  - webapps
products:
  - Casdoor 3.54.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.exploit-db.com/exploits/52584
rules:
  - title: Detect Casdoor Path Traversal Attempt
    description: Detects path traversal attempts targeting Casdoor via HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Casdoor File Write via Path Traversal
    description: Detects potential file writes resulting from path traversal in Casdoor based on HTTP POST requests with specific content types and path traversal sequences.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1565.001
    data_sources:
      - webserver
rules_count: 2
---

A path traversal vulnerability affects Casdoor version 3.54.1, enabling attackers to write arbitrary files to the server's file system. This flaw can be exploited to overwrite critical system files, inject malicious code into web application directories, or deface the web application. The existence of a public exploit (EDB-52584) on Exploit-DB significantly increases the likelihood of exploitation. Successful exploitation could lead to remote code execution or denial of service. Organizations using this version of Casdoor should prioritize patching or mitigating this vulnerability to prevent potential attacks.

## Attack Chain

1.  Attacker identifies a Casdoor 3.54.1 instance exposed to the internet.
2.  Attacker crafts a malicious HTTP request targeting a file upload or file write endpoint.
3.  The request includes a path traversal sequence (e.g., "../") in the filename or path parameter.
4.  Casdoor fails to properly sanitize the path, allowing the attacker to bypass directory restrictions.
5.  The attacker specifies a target file outside of the intended upload directory.
6.  Casdoor writes attacker-controlled data to the specified file, overwriting its contents.
7.  If the overwritten file is a configuration file or executable, the attacker can gain control of the application.
8.  The attacker achieves arbitrary code execution on the server.

## Impact

Successful exploitation of this vulnerability allows an attacker to write arbitrary files to the Casdoor server's file system. This can lead to the overwriting of critical system files, potentially causing a denial of service. Alternatively, attackers can inject malicious code into web application directories, leading to remote code execution. The availability of a public exploit makes unpatched systems particularly vulnerable.

## Recommendation

*   Upgrade to a patched version of Casdoor to remediate the vulnerability.
*   Deploy the Sigma rules provided to detect path traversal attempts in web server logs.
*   Implement strict input validation and sanitization for all file paths and filenames handled by Casdoor to prevent path traversal attacks.
*   Monitor web server logs for suspicious file access patterns, especially those involving path traversal sequences.
