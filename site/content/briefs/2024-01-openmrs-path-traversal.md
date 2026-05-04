---
title: OpenMRS ModuleResourcesServlet Path Traversal Vulnerability
slug: 2024-01-openmrs-path-traversal
description: OpenMRS Core versions 2.7.8 and earlier, as well as versions 2.8.0 through 2.8.5, contain a path traversal vulnerability in the ModuleResourcesServlet, allowing an unauthenticated attacker to read arbitrary files from the server filesystem by manipulating the URL.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - information-disclosure
  - openmrs
vendors:
  - Apache
  - OpenMRS
products:
  - Tomcat
  - OpenMRS Core
  - openmrs-web
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-jjgj-cx3q-pw4w
rules:
  - title: Detect OpenMRS Path Traversal Attempt via ModuleResourcesServlet
    description: Detects potential path traversal attempts targeting the OpenMRS ModuleResourcesServlet by identifying suspicious URL patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenMRS Path Traversal Response
    description: Detects a successful path traversal attempt in OpenMRS by identifying the retrieval of sensitive files (e.g., /etc/passwd).
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenMRS Core, a widely used open-source medical record system, is vulnerable to a path traversal attack via the `ModuleResourcesServlet`. This flaw affects versions up to 2.7.8 and versions 2.8.0 through 2.8.5. An unauthenticated attacker can exploit this vulnerability by crafting a malicious URL to read arbitrary files from the server's filesystem. The vulnerability exists because the `ModuleResourcesServlet` component fails to properly validate user-supplied path input when serving static module resources. This vulnerability is particularly critical because the affected endpoint is not protected by authentication filters, and successful exploitation depends on running Apache Tomcat versions before 8.5.31 or prior to 9.0.10.

## Attack Chain

1. The attacker identifies a vulnerable OpenMRS instance running on a susceptible Tomcat version.
2. The attacker identifies a valid module ID installed on the target OpenMRS instance (e.g., `legacyui`).
3. The attacker crafts a malicious HTTP GET request to the `/openmrs/moduleResources/{moduleid}` endpoint containing a path traversal sequence (e.g., `..;`) within the URL. The request attempts to access a sensitive file, such as `/etc/passwd`.
4. The `ModuleResourcesServlet` receives the request and extracts the path information without proper validation.
5. The application constructs a file path by concatenating the web application root, module path, module ID, "resources," and the attacker-supplied path.
6. Due to missing path sanitization and normalization, the resulting file path points to the attacker-specified file outside the intended resources directory.
7. The server reads the content of the arbitrary file (e.g., `/etc/passwd`).
8. The server returns the file content in the HTTP response to the attacker, resulting in information disclosure.

## Impact

Successful exploitation allows an unauthenticated attacker to read arbitrary files on the OpenMRS server. This can lead to the exposure of sensitive information, including system configuration files containing database credentials, potentially compromising the entire application and patient data. The number of affected deployments is unknown, but any OpenMRS instance running vulnerable versions on older Tomcat installations is at risk.

## Recommendation

*   Upgrade OpenMRS Core to a patched version beyond 2.8.5 to address CVE-2026-40075.
*   As a short-term mitigation, upgrade Apache Tomcat to version 8.5.31 or later, or 9.0.10 or later, to leverage container-level path traversal protection.
*   Deploy the following Sigma rule to detect exploitation attempts against the vulnerable `ModuleResourcesServlet` endpoint.
*   Monitor web server logs for suspicious URL patterns containing path traversal sequences (`../`, `..;`, `%2e%2e%2f`) targeting the `/openmrs/moduleResources/` path.
