---
title: PyLoad Path Traversal Vulnerability in set_package_data
slug: 2026-05-pyload-path-traversal
description: PyLoad versions 0.5.0b3.dev99 and earlier are vulnerable to a path traversal vulnerability in the `set_package_data` function, allowing attackers to write files to arbitrary directories with the privileges of the PyLoad process.
date: "2026-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - pyload
vendors:
  - pip
products:
  - pyload-ng (<= 0.5.0b3.dev99)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Relationships
references:
  - https://github.com/advisories/GHSA-838g-gr43-qqg9
rules:
  - title: Detect PyLoad set_package_data Path Traversal
    description: Detects potential path traversal attempts in PyLoad's set_package_data API by monitoring for suspicious folder paths.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1553.004
    data_sources:
      - webserver
      - linux
  - title: Detect PyLoad API Misuse via Request Headers
    description: Detects potential unauthorized access to the PyLoad API by monitoring for suspicious API key usage or missing X-API-Key header.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PyLoad, a free and open-source download manager, is vulnerable to a path traversal vulnerability within its `set_package_data` API function. Specifically, versions up to and including 0.5.0b3.dev99 fail to properly sanitize the package folder name. This lack of sanitization allows a user with `Perms.MODIFY` to specify arbitrary directories as download locations for a package. An attacker can leverage this flaw to write files outside the intended download directory, potentially leading to arbitrary code execution if the PyLoad process has sufficient privileges. The vulnerability was disclosed in GHSA-838g-gr43-qqg9 on May 5, 2026.

## Attack Chain

1. The attacker gains access to the PyLoad API, potentially through leaked credentials or other vulnerabilities.
2. The attacker crafts a POST request to the `/api/add_package` endpoint to create a new package with a specified name and download link (e.g., `http://example.com/file.txt`). The response includes the assigned package ID.
3. The attacker crafts a POST request to the `/api/set_package_data` endpoint, targeting the newly created package ID.
4. Within the JSON payload for `set_package_data`, the attacker includes a `data` object with the key `_folder` set to an absolute path containing directory traversal sequences (e.g., `/users/root/`).
5. The PyLoad application, lacking proper sanitization, accepts the attacker-controlled path as the download location.
6. The attacker triggers a download associated with the package.
7. PyLoad attempts to write downloaded files to the attacker-specified path (e.g., `/users/root/`), potentially overwriting existing files or creating new ones.
8. The attacker achieves arbitrary file write, leading to potential privilege escalation or code execution if writable locations like system configuration files are targeted.

## Impact

Successful exploitation allows an attacker to write files to arbitrary locations on the file system with the privileges of the PyLoad process. This could lead to privilege escalation, arbitrary code execution, or denial of service. Given that PyLoad is often deployed on personal servers or NAS devices, the impact could range from data theft to complete system compromise. Affected versions include all PyLoad versions up to and including 0.5.0b3.dev99.

## Recommendation

*   Upgrade PyLoad to a version beyond 0.5.0b3.dev99 that includes the patch for CVE-2026-42315.
*   Deploy the Sigma rule `Detect PyLoad set_package_data Path Traversal` to detect attempts to exploit this vulnerability by monitoring for suspicious folder paths in `set_package_data` requests.
*   Monitor web server logs for POST requests to `/api/set_package_data` with suspicious `_folder` values containing absolute paths and directory traversal sequences.
*   Review and restrict API access to PyLoad to only trusted sources to mitigate the risk of unauthorized exploitation.
