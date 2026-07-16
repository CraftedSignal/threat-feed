---
title: Lenovo App Store Path Traversal Vulnerability (CVE-2026-13103) Leading to Arbitrary Code Execution
slug: 2026-07-lenovo-app-store-pathtraversal
description: A critical path traversal vulnerability, identified as CVE-2026-13103, exists in the Lenovo App Store, enabling a local authenticated user to achieve arbitrary code execution on affected Windows systems within the Chinese market.
date: "2026-07-16T17:19:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-traversal
  - rce
  - lenovo
vendors:
  - Lenovo
products:
  - Lenovo App Store
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A potential path traversal vulnerability was reported in Lenovo App Store... that could allow a local authenticated user to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-13103
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13103
  - https://iknow.lenovo.com.cn/detail/441419
---

A significant path traversal vulnerability (CVE-2026-13103) has been reported in the Lenovo App Store, an application distributed exclusively in the Chinese market. This flaw, categorized as CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), allows a local authenticated user to execute arbitrary code. The vulnerability affects versions of the Lenovo App Store prior to 9.0.2930.0514 running on Windows operating systems. Successful exploitation could lead to an attacker running malicious code with the privileges of the authenticated user, potentially facilitating further compromise, data manipulation, or system instability. The vulnerability has a CVSS v3.1 base score of 7.3 (High) and requires user interaction for exploitation.

## Attack Chain

1. A local, authenticated user gains access to a Windows system with the vulnerable Lenovo App Store installed.
2. The user identifies the path traversal vulnerability within specific functionalities of the Lenovo App Store.
3. The user crafts malicious input containing directory traversal sequences (e.g., `../`, `..\`) intended for a file path or similar parameter within the application.
4. The Lenovo App Store processes this malformed input, failing to properly sanitize or validate the path.
5. This allows the attacker to write or modify files outside of the intended, restricted directories, potentially into critical system locations or user-controlled execution paths.
6. The attacker places a malicious executable or script in a location from which it will be executed (e.g., a startup folder, an overwritten legitimate application binary, or a user-invoked path).
7. Upon subsequent user interaction with the application or system, the malicious code is executed.
8. Arbitrary code execution is achieved under the context of the local authenticated user.

## Impact

Successful exploitation of CVE-2026-13103 can lead to arbitrary code execution within the context of the local authenticated user on affected Windows systems. This could allow an attacker to install additional malicious software, modify system configurations, access or exfiltrate sensitive data, or establish persistence. While this vulnerability requires prior local authentication and user interaction, it significantly escalates the potential for damage once an attacker has established a foothold on a system. The impact is primarily confined to users of the Lenovo App Store in the Chinese market.

## Recommendation

* Immediately update the Lenovo App Store to version 9.0.2930.0514 or later to patch CVE-2026-13103.
* Regularly review and enforce principle of least privilege for all local user accounts to minimize the potential impact of successful local exploits.
