---
title: KodExplorer Path Traversal Vulnerability (CVE-2026-6568)
slug: 2026-04-kodexplorer-path-traversal
description: KodExplorer up to version 4.52 is vulnerable to a path traversal attack via manipulation of the path argument in the share.class.php::initShareOld function, potentially allowing remote attackers to access sensitive files.
date: "2026-04-19T10:16:09Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - path-traversal
  - kodexplorer
  - cve-2026-6568
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6568
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6568
  - https://vuldb.com/submit/789981
  - https://vuldb.com/vuln/358202
  - https://vuldb.com/vuln/358202/cti
  - https://vulnplus-note.wetolink.com/share/JyHBnRUaoOY2
iocs:
  - type: url
    value: https://vulnplus-note.wetolink.com/share/JyHBnRUaoOY2
ioc_counts:
  url: 1
rules:
  - title: Detect KodExplorer Path Traversal Attempt
    description: Detects path traversal attempts targeting the KodExplorer share.class.php endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Double Encoding Path Traversal in KodExplorer
    description: Detects path traversal attempts using double URL encoding in KodExplorer requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-6568, affects kodcloud KodExplorer up to version 4.52. The vulnerability resides within the `share.class.php::initShareOld` function in the `/app/controller/share.class.php` file, a part of the Public Share Handler component. An attacker can exploit this flaw by manipulating the `path` argument, leading to unauthorized access to files and directories outside of the intended share path. Public exploit code is available, increasing the risk of active exploitation. The vendor was notified, but has not responded.

## Attack Chain

1.  An attacker identifies a KodExplorer instance running version 4.52 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the `/app/controller/share.class.php` endpoint.
3.  The request includes a manipulated `path` argument designed to traverse directories outside the intended share path (e.g., `../../../../etc/passwd`).
4.  The `share.class.php::initShareOld` function processes the request without proper sanitization of the `path` argument.
5.  The application attempts to access the file specified by the attacker-controlled path.
6.  If successful, the application reads and potentially displays the contents of the targeted file (e.g., `/etc/passwd`) to the attacker.
7.  The attacker analyzes the retrieved information to gather sensitive data, such as usernames, system configurations, or database credentials.
8.  The attacker leverages the compromised information to further compromise the system or gain access to other sensitive resources.

## Impact

Successful exploitation of CVE-2026-6568 can allow an unauthenticated remote attacker to read arbitrary files on the KodExplorer server. This may lead to the disclosure of sensitive information such as configuration files, user credentials, or source code. The vulnerability poses a significant risk to organizations using affected versions of KodExplorer. The number of potential victims is unknown, but it is likely to affect any organization using the vulnerable software.

## Recommendation

*   Apply input validation to the `path` parameter within the `share.class.php::initShareOld` function to prevent path traversal (reference CVE-2026-6568).
*   Deploy the Sigma rule "Detect KodExplorer Path Traversal Attempt" to identify malicious requests targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious requests containing path traversal sequences (e.g., "../", "..\", "%2e%2e/").
*   Block access to the malicious URLs listed in the IOC table at the network perimeter.
