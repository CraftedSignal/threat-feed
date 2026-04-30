---
title: Xerte Online Toolkits Path Traversal Vulnerability
slug: 2024-01-xerte-path-traversal
description: Xerte Online Toolkits 3.15 and earlier are vulnerable to relative path traversal, allowing attackers to move files and potentially achieve remote code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - remote-code-execution
  - xss
vendors:
  - Xerte
products:
  - Xerte Online Toolkits (<= 3.15)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unprotected Credentials
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unprotected Credentials
cves:
  - id: CVE-2026-34414
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34414
rules:
  - title: Detect Suspicious Path Traversal in Xerte Connector
    description: Detects attempts to exploit the path traversal vulnerability in the Xerte Online Toolkits elFinder connector by monitoring requests with directory traversal sequences in the 'name' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PHP Execution from Web Root
    description: Detects execution of PHP files from the web root directory, which may indicate exploitation of a path traversal vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Xerte Online Toolkits, a tool used to create online learning materials, is vulnerable to a path traversal vulnerability (CVE-2026-34414) in versions 3.15 and earlier. The vulnerability exists in the elFinder connector endpoint at `/editor/elfinder/php/connector.php`. The `name` parameter within rename commands is not properly sanitized, allowing attackers to use directory traversal sequences (e.g., `../`) to manipulate file locations. This flaw can be exploited to overwrite application files, inject stored cross-site scripting (XSS), or, when combined with other vulnerabilities, achieve unauthenticated remote code execution (RCE). This poses a significant threat to organizations utilizing affected versions of Xerte Online Toolkits, potentially leading to data breaches, system compromise, and reputational damage.

## Attack Chain

1.  An attacker identifies a vulnerable Xerte Online Toolkits instance running version 3.15 or earlier.
2.  The attacker crafts a malicious HTTP request to `/editor/elfinder/php/connector.php` targeting the rename command.
3.  Within the request, the `name` parameter contains directory traversal sequences (e.g., `../../`) and the desired destination path.
4.  The server, due to insufficient input validation, processes the request without properly sanitizing the `name` parameter.
5.  The attacker moves a file (e.g., an uploaded image or media file) from its original project media directory to a new location specified within the malicious `name` parameter. This could involve moving a file to the application root directory.
6.  If the attacker moves a specifically crafted PHP file to the application root and the webserver is configured to execute PHP files in the root, the attacker can then access this file via a web request.
7.  The attacker executes arbitrary code on the server.
8.  The attacker gains complete control of the Xerte Online Toolkits instance and potentially the underlying server.

## Impact

Successful exploitation of this vulnerability can lead to several critical consequences. Attackers can overwrite sensitive application files, leading to denial of service or system instability. The injection of malicious JavaScript code can result in stored cross-site scripting (XSS) attacks, compromising user accounts and data. The most severe outcome is unauthenticated remote code execution (RCE), enabling attackers to gain complete control over the affected server, potentially leading to data breaches, malware deployment, and further lateral movement within the network. The CVSS v3.1 base score for this vulnerability is 7.1, indicating a high level of risk.

## Recommendation

*   Upgrade Xerte Online Toolkits to a version greater than 3.15 to patch CVE-2026-34414.
*   Deploy the Sigma rule `Detect Suspicious Path Traversal in Xerte Connector` to identify attempted exploitation of the path traversal vulnerability by monitoring requests to `/editor/elfinder/php/connector.php` with directory traversal sequences.
*   Implement input validation and sanitization on the `name` parameter within the elFinder connector to prevent path traversal attacks.
*   Review web server configurations to prevent the execution of PHP files from the web root directory.
