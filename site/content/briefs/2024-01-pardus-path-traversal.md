---
title: Pardus Software Center Path Traversal Vulnerability (CVE-2026-5166)
slug: 2024-01-pardus-path-traversal
description: CVE-2026-5166 is a path traversal vulnerability affecting TUBITAK BILGEM Software Technologies Research Institute Pardus Software Center before version 1.0.3, allowing attackers to bypass directory restrictions.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-5166
  - path-traversal
  - web-application
vendors:
  - TUBITAK BILGEM Software Technologies Research Institute
products:
  - Pardus Software Center
affected_os:
  - Pardus Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5166
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5166
rules:
  - title: Pardus Software Center Path Traversal Attempt
    description: Detects path traversal attempts targeting Pardus Software Center via HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Pardus Software Center Path Traversal - Double Encoding
    description: Detects path traversal attempts using double encoding to bypass sanitization
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

CVE-2026-5166 is a critical path traversal vulnerability discovered in TUBITAK BILGEM Software Technologies Research Institute Pardus Software Center, affecting versions prior to 1.0.3. This vulnerability allows an attacker to bypass directory restrictions and potentially access sensitive files or execute arbitrary code on the underlying system. Path traversal vulnerabilities arise when an application does not properly sanitize user-supplied input used to construct file paths. This can lead to unauthorized access and modification of data, potentially leading to a full system compromise. The vulnerability was published on 2026-04-29, but due to its severity, detection engineers should prioritize creating detections for it.

## Attack Chain

1.  The attacker identifies an endpoint in Pardus Software Center that accepts file paths as input.
2.  The attacker crafts a malicious request containing a path traversal payload, such as "../../../etc/passwd".
3.  The application fails to properly sanitize the input, allowing the path traversal sequence to be processed.
4.  The application constructs a file path using the unsanitized input, effectively escaping the intended directory.
5.  The application attempts to access the file specified by the attacker-controlled path.
6.  If successful, the attacker can read sensitive files such as configuration files, user data, or system binaries.
7.  The attacker may leverage the ability to read sensitive files to gain further information about the system, such as user credentials or system configuration.
8.  The attacker can then exploit this information to escalate privileges or compromise other parts of the system.

## Impact

Successful exploitation of CVE-2026-5166 can lead to unauthorized access to sensitive data, including configuration files, user data, and system binaries. This could allow an attacker to steal credentials, escalate privileges, or compromise the entire system. Given the CVSS v3.1 base score of 9.6, this vulnerability poses a critical risk to systems running affected versions of Pardus Software Center. The exact number of affected systems is currently unknown, but organizations using this software are urged to apply mitigations immediately.

## Recommendation

*   Upgrade Pardus Software Center to version 1.0.3 or later to patch CVE-2026-5166.
*   Deploy the Sigma rule `Pardus Software Center Path Traversal Attempt` to detect exploitation attempts in web server logs.
*   Monitor web server logs for suspicious requests containing path traversal sequences like "../" or "..\" to detect potential exploitation attempts.
