---
title: Fujian Apex LiveBOS Path Traversal Vulnerability
slug: 2026-05-livebos-path-traversal
description: A path traversal vulnerability exists in Fujian Apex LiveBOS version 2.0 and earlier, allowing remote attackers to read arbitrary files by manipulating the filename argument in the /feed/UploadImage.do endpoint.
date: "2026-05-01T01:16:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - cve-2026-7519
vendors:
  - Fujian Apex
products:
  - LiveBOS (<= 2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7519
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7519
  - https://my.feishu.cn/docx/TCyMdptvaoTQCvxkHLbceJZCnge?from=from_copylink
  - https://vuldb.com/vuln/360333
rules:
  - title: Detect LiveBOS Path Traversal Attempt
    description: Detects path traversal attempts in Fujian Apex LiveBOS via the filename parameter in UploadImage.do
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect LiveBOS File Access via Path Traversal
    description: Detects access to sensitive files (e.g., /etc/passwd) via path traversal in Fujian Apex LiveBOS
    platform: sigma
    severity: critical
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Fujian Apex LiveBOS, a live broadcasting system, is vulnerable to a path traversal attack. This vulnerability, identified as CVE-2026-7519, exists due to insufficient input validation on the filename parameter within the /feed/UploadImage.do endpoint. Versions up to and including 2.0 are affected. Publicly available exploits exist, increasing the risk of exploitation. An attacker can leverage this flaw to access sensitive files on the server, potentially leading to information disclosure or further system compromise. Upgrading to version 2.1 or applying available patches is strongly recommended.

## Attack Chain

1. An attacker identifies a Fujian Apex LiveBOS instance running version 2.0 or earlier.
2. The attacker crafts a malicious HTTP request targeting the /feed/UploadImage.do endpoint.
3. The attacker manipulates the filename parameter within the request, injecting path traversal sequences (e.g., ../../).
4. The server-side application fails to properly sanitize the filename, allowing the path traversal sequence to be processed.
5. The application attempts to read a file based on the attacker-controlled path.
6. If successful, the contents of the targeted file are returned to the attacker in the HTTP response.
7. The attacker analyzes the leaked file content for sensitive information (e.g., credentials, configuration files).

## Impact

Successful exploitation of this vulnerability can lead to unauthorized access to sensitive files on the LiveBOS server. This could include configuration files containing database credentials, private keys, or other confidential information. The impact ranges from information disclosure to potential full system compromise, depending on the accessed data. There are no reported victims or sectors targeted as of yet, but the public availability of the exploit increases the likelihood of exploitation.

## Recommendation

*   Upgrade Fujian Apex LiveBOS to version 2.1 to remediate CVE-2026-7519.
*   Deploy the Sigma rule `Detect LiveBOS Path Traversal Attempt` to identify malicious requests exploiting the vulnerability.
*   Monitor web server logs for requests containing path traversal sequences targeting the `/feed/UploadImage.do` endpoint.
