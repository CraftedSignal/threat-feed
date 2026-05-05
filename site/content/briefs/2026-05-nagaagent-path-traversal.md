---
title: RTGS2017 NagaAgent Path Traversal Vulnerability
slug: 2026-05-nagaagent-path-traversal
description: RTGS2017 NagaAgent up to version 5.1.0 is vulnerable to path traversal via manipulation of the 'Name' argument in the Skills Endpoint, potentially leading to unauthorized file access.
date: "2026-05-05T00:16:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - path-traversal
  - web-application
  - cve-2026-7784
vendors:
  - RTGS2017
products:
  - NagaAgent (<= 5.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2026-7784
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7784
  - https://github.com/RTGS2017/NagaAgent/
  - https://github.com/RTGS2017/NagaAgent/issues/311
  - https://vuldb.com/vuln/360981
rules:
  - title: Detect RTGS2017 NagaAgent Path Traversal Attempt
    description: Detects potential path traversal attempts targeting RTGS2017 NagaAgent by monitoring for common path traversal sequences in HTTP requests to the Skills Endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect Double Encoding Path Traversal in RTGS2017 NagaAgent
    description: Detects path traversal attempts using double encoding to bypass input validation in RTGS2017 NagaAgent.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

RTGS2017 NagaAgent, a software application, is susceptible to a path traversal vulnerability (CVE-2026-7784) affecting versions up to 5.1.0. The vulnerability lies within the Skills Endpoint, specifically during the processing of the `Name` argument in the `apiserver/routes/extensions.py` file. An attacker can remotely exploit this flaw to gain unauthorized access to files and directories on the system. A public exploit is available, increasing the risk of exploitation. The vendor has been notified, but has yet to respond to the vulnerability report. This lack of response elevates concern as the vulnerability has been actively disclosed.

## Attack Chain

1.  Attacker identifies a vulnerable RTGS2017 NagaAgent instance running version 5.1.0 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the Skills Endpoint.
3.  The malicious request includes a `Name` argument with path traversal characters (e.g., `../`, `..\\`).
4.  The application fails to properly sanitize the `Name` argument before using it to construct a file path.
5.  The application attempts to access a file or directory outside of the intended base directory.
6.  The attacker gains unauthorized access to sensitive files or directories on the server, potentially including configuration files or user data.
7.  The attacker leverages the exposed information to further compromise the system or network.

## Impact

Successful exploitation of this path traversal vulnerability allows attackers to read arbitrary files on the affected system. This can lead to the exposure of sensitive information such as configuration files, credentials, or user data. An attacker could potentially leverage this access to escalate privileges, move laterally within the network, or cause denial of service. The full scope of impact depends on the specific files and directories that are accessible to the attacker.

## Recommendation

*   Upgrade RTGS2017 NagaAgent to a patched version that addresses CVE-2026-7784 (if a patch becomes available).
*   Implement input validation on the `Name` argument within the Skills Endpoint to prevent path traversal attacks.
*   Deploy the Sigma rule "Detect RTGS2017 NagaAgent Path Traversal Attempt" to identify exploitation attempts.
*   Monitor web server logs for suspicious requests containing path traversal sequences targeting the `apiserver/routes/extensions.py` endpoint.
