---
title: Adobe ColdFusion Path Traversal Vulnerability (CVE-2026-34619)
slug: 2026-04-coldfusion-path-traversal
description: A path traversal vulnerability (CVE-2026-34619) in Adobe ColdFusion versions 2023.18, 2025.6, and earlier allows an attacker to bypass security features and access unauthorized files or directories without user interaction.
date: "2026-04-15T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - coldfusion
  - cve-2026-34619
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34619
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34619
  - https://helpx.adobe.com/security/products/coldfusion/apsb26-38.html
rules:
  - title: Detect ColdFusion Path Traversal Attempts
    description: Detects potential path traversal attempts targeting Adobe ColdFusion servers by looking for '../' sequences in URI queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows|linux
  - title: Detect ColdFusion Path Traversal via Double Encoding
    description: Detects path traversal attempts in Adobe ColdFusion that may be obfuscated using double URL encoding.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows|linux
rules_count: 2
---

CVE-2026-34619 describes a path traversal vulnerability affecting Adobe ColdFusion versions 2023.18, 2025.6, and earlier. Disclosed on April 14, 2026, this vulnerability allows an attacker to bypass intended security restrictions and gain access to sensitive files and directories on the ColdFusion server. The vulnerability exists due to improper limitation of pathnames, and successful exploitation requires no user interaction, making it particularly dangerous. This issue could lead to the exposure of configuration files, source code, or other sensitive data, potentially compromising the entire ColdFusion application and the server it resides on. Organizations using these versions of ColdFusion are vulnerable.

## Attack Chain

1.  The attacker identifies a ColdFusion server running a vulnerable version (2023.18, 2025.6, or earlier).
2.  The attacker crafts a malicious HTTP request containing a path traversal sequence (e.g., "../") in a URL parameter that is used to access files.
3.  The ColdFusion server improperly processes the path, failing to adequately restrict access to files within the intended directory.
4.  The attacker bypasses security restrictions and gains access to files or directories outside of the intended web root.
5.  The attacker reads sensitive configuration files, such as database connection strings or API keys.
6.  The attacker leverages exposed credentials to gain unauthorized access to databases or other systems.
7.  The attacker modifies application code or uploads malicious files to further compromise the server.

## Impact

Successful exploitation of CVE-2026-34619 can lead to a complete compromise of the ColdFusion server. An attacker could steal sensitive data, including customer information, proprietary source code, and database credentials. This could result in significant financial losses, reputational damage, and legal repercussions for affected organizations. The lack of required user interaction makes this vulnerability particularly dangerous, as an attacker can exploit it without any user awareness.

## Recommendation

*   Upgrade to a patched version of Adobe ColdFusion as soon as possible. Refer to Adobe's security bulletin APSB26-38 for the latest updates and instructions (https://helpx.adobe.com/security/products/coldfusion/apsb26-38.html).
*   Implement the Sigma rule "Detect ColdFusion Path Traversal Attempts" to detect exploitation attempts in web server logs.
*   Continuously monitor web server logs for suspicious URL patterns and path traversal attempts.
