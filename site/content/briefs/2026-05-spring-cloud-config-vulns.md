---
title: Spring Cloud Config Vulnerabilities Allow Secret Access and Directory Traversal
slug: 2026-05-spring-cloud-config-vulns
description: Multiple vulnerabilities in Spring Cloud Config, including CVE-2026-40981, CVE-2026-40982, and CVE-2026-41002, could allow unauthorized access to secrets and directory traversal attacks, potentially leading to data exposure and system compromise.
date: "2026-05-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - spring
  - cloud
  - config
  - vulnerability
  - directory_traversal
  - secret_access
vendors:
  - Spring
products:
  - Spring Cloud Config
cves:
  - id: CVE-2026-40981
    cvss: 7.5
  - id: CVE-2026-40982
    cvss: 9.1
  - id: CVE-2026-41002
    cvss: 7.2
references:
  - https://cyber.gc.ca/en/alerts-advisories/spring-security-advisory-av26-431
  - https://spring.io/security/cve-2026-40981
  - https://spring.io/security/cve-2026-40982
  - https://spring.io/security/cve-2026-41002
  - https://spring.io/security
rules:
  - title: Detect Directory Traversal Attempts Against Spring Cloud Config Server
    description: Detects attempts to exploit directory traversal vulnerabilities (e.g., CVE-2026-40982) against Spring Cloud Config servers by identifying suspicious URL patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Sensitive Configuration Endpoints
    description: Detects access to potentially sensitive configuration endpoints on Spring Cloud Config servers that might indicate CVE-2026-40981 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On May 6, 2026, Spring released security advisories addressing critical vulnerabilities in Spring Cloud Config. These vulnerabilities impact multiple versions of Spring Cloud Config and can lead to serious security breaches. The most critical issue, CVE-2026-40981, allows Spring Cloud Config clients to access secrets from any project the Config Server has access to on Google Secrets Manager. Additionally, CVE-2026-40982 describes a directory traversal vulnerability, and CVE-2026-41002 details a TOCTOU attack vulnerability. Successful exploitation of these vulnerabilities can result in unauthorized data access, code execution, and complete system compromise. Defenders need to apply the necessary updates immediately.

## Attack Chain

1. An attacker identifies a vulnerable Spring Cloud Config server exposed to the internet or an internal network.
2. For CVE-2026-40981, the attacker crafts a request to the vulnerable server, targeting a specific configuration endpoint.
3. The request bypasses access controls due to the vulnerability, allowing access to configuration data from other projects accessible by the Config Server.
4. The attacker extracts sensitive information, such as API keys, database credentials, or other secrets, from the exposed configuration data.
5. For CVE-2026-40982, the attacker crafts a malicious request containing directory traversal sequences (e.g., "../") to access files outside the intended configuration directory.
6. The server processes the request without proper validation, allowing the attacker to read arbitrary files on the system.
7. The attacker gains access to sensitive files, such as application code, configuration files, or user data.
8. The attacker leverages the obtained information or code execution capabilities to further compromise the system or network.

## Impact

Successful exploitation of these vulnerabilities can have severe consequences. CVE-2026-40981 allows unauthorized access to sensitive configuration data, potentially exposing credentials and API keys, leading to data breaches and unauthorized access to other systems. CVE-2026-40982 enables directory traversal, allowing attackers to read arbitrary files on the server, potentially exposing application source code, sensitive data, and internal configurations. A successful TOCTOU attack via CVE-2026-41002 could lead to inconsistent configuration states, resulting in application malfunction or unauthorized access.

## Recommendation

*   Apply the security updates provided by Spring to address CVE-2026-40981, CVE-2026-40982, and CVE-2026-41002 on all Spring Cloud Config instances immediately.
*   Monitor web server logs for suspicious requests containing directory traversal sequences (e.g., "../") targeting Spring Cloud Config endpoints to detect potential CVE-2026-40982 exploitation. Deploy the Sigma rule detecting directory traversal attempts against Spring Cloud Config servers.
*   Implement strict access controls and network segmentation to limit the scope of potential damage from CVE-2026-40981. Review and validate the configuration of Google Secrets Manager and Spring Cloud Config to ensure proper isolation of secrets.
