---
title: OpenMRS Module Upload Path Traversal Vulnerability
slug: 2024-01-openmrs-zip-slip
description: OpenMRS versions 2.7.8 and earlier, as well as versions 2.8.0 through 2.8.5, are vulnerable to a path traversal (Zip Slip) attack via the `POST /openmrs/ws/rest/v1/module` endpoint that allows authenticated attackers to achieve arbitrary file write and remote code execution.
date: "2026-05-04T17:39:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - zip-slip
  - rce
  - openmrs
  - web-application
vendors:
  - OpenMRS
products:
  - openmrs-web (<= 2.7.8)
  - openmrs-web (>= 2.8.0, <= 2.8.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-78fc-9688-w8xw
rules:
  - title: Detect OpenMRS Malicious Module Upload
    description: Detects attempts to upload malicious modules to OpenMRS via the REST API endpoint with suspicious file extensions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect JSP File Creation in Web Application Root
    description: Detects the creation of JSP files in the web application root, which may indicate exploitation of a path traversal vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenMRS, an open-source enterprise electronic medical record system platform, is vulnerable to a path traversal (Zip Slip) vulnerability in its module upload functionality. Discovered in versions 2.7.8 and earlier, as well as versions 2.8.0 through 2.8.5, the vulnerability resides in the `POST /openmrs/ws/rest/v1/module` endpoint. An authenticated attacker with administrative privileges can exploit this flaw by uploading a specially crafted `.omod` archive containing malicious ZIP entries with directory traversal sequences. This can allow the attacker to write files outside of the intended module directory, potentially leading to arbitrary file write and remote code execution on the server. The vulnerability stems from incomplete path validation within the `WebModuleUtil.startModule()` function, an oversight compared to other extraction methods within the same codebase that are properly protected.

## Attack Chain

1. The attacker authenticates to the OpenMRS instance with valid admin credentials via Basic Auth.
2. The attacker crafts a malicious `.omod` file containing a ZIP entry with a path traversal payload, such as `web/module/../../../../<target_filename>.jsp`.
3. The attacker sends a `POST` request to the `/openmrs/ws/rest/v1/module` endpoint, uploading the malicious `.omod` file.
4. The server receives the request and parses the uploaded `.omod` file, treating it as a ZIP archive.
5. During module loading via `WebModuleUtil.startModule()`, the server extracts entries under the `web/module/` directory.
6. Due to an incomplete check, the entry `web/module/../../../../<target_filename>.jsp` passes the initial validation.
7. The server attempts to write the extracted file to a path constructed by concatenating the traversed path, resulting in writing the file outside the intended `WEB-INF/view/module/` directory.
8. If the written file is a JSP script, accessing it via a browser triggers server-side execution, achieving Remote Code Execution (RCE).

## Impact

Successful exploitation of this vulnerability allows an attacker to write arbitrary files within the web application root directory of the OpenMRS instance. This can lead to remote code execution, allowing the attacker to gain complete control of the affected server. Given OpenMRS's use in healthcare environments, a successful attack could compromise sensitive patient data, disrupt medical operations, and damage the reputation of the affected organization. The number of potentially affected installations is unknown, but the vulnerability impacts a widely used version of the platform.

## Recommendation

*   Apply the patch or upgrade to a version of OpenMRS that includes the fix for CVE-2026-40076 to address the path traversal vulnerability.
*   Deploy the Sigma rule `Detect OpenMRS Malicious Module Upload` to identify exploitation attempts based on HTTP requests to the `/openmrs/ws/rest/v1/module` endpoint with suspicious file extensions in the query parameters.
*   Enable webserver logging to capture HTTP request data and facilitate detection and investigation efforts.
*   Monitor file creation events within the web application root directory for suspicious JSP files. Use the Sigma rule `Detect JSP File Creation in Web Application Root` as a starting point.
*   Enforce the `module.allow_web_admin` restriction consistently across all module upload entry points, including the REST API to prevent bypass.
