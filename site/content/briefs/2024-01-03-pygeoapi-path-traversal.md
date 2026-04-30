---
title: pygeoapi Path Traversal Vulnerability in STAC FileSystemProvider
slug: 2024-01-03-pygeoapi-path-traversal
description: A path traversal vulnerability exists in pygeoapi versions 0.23.0 to 0.23.2 within the STAC FileSystemProvider plugin, allowing unauthenticated access to directories when deployed without a URL-normalizing proxy.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - webserver
products:
  - pygeoapi
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Resource Development
    technique_id: T1552
    technique_name: Unprotected Credentials
references:
  - https://github.com/advisories/GHSA-f6pr-83pg-ghh6
  - https://github.com/geopython/pygeoapi/commit/bf25b8695edbdd5476eeffc102b633d1d3e45f52
rules:
  - title: pygeoapi Path Traversal Attempt
    description: Detects path traversal attempts in pygeoapi by monitoring for '..' sequences in HTTP request URIs targeting STAC collection endpoints.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-42351
      - resource_development
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
  - title: pygeoapi Suspicious HTTP Status Code After Path Traversal Attempt
    description: Detects suspicious HTTP status codes (403, 404, 500) following path traversal attempts in pygeoapi requests.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-42351
      - resource_development
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability has been identified in pygeoapi versions 0.23.0, 0.23.1, and 0.23.2, specifically within the STAC (Spatially Aware Catalog) FileSystemProvider plugin. This flaw allows unauthenticated attackers to access unauthorized directories by manipulating URL paths, particularly when pygeoapi is deployed without a proxy or web front end that normalizes URLs containing `..` sequences. The vulnerability arises from improper handling of raw string path concatenation, making systems with STAC collection-based resources in their configuration susceptible to unauthorized file system access. This issue was resolved in version 0.23.3.

## Attack Chain

1.  An attacker crafts a malicious HTTP request targeting a pygeoapi instance configured with a STAC collection resource.
2.  The crafted request includes a URL containing path traversal sequences (e.g., `../`) to navigate the file system.
3.  pygeoapi's STAC FileSystemProvider plugin receives the request and attempts to resolve the file path.
4.  Due to the raw string path concatenation vulnerability, the path traversal sequences are not properly sanitized.
5.  The application constructs an incorrect file path, allowing access to files and directories outside of the intended STAC collection directory.
6.  The attacker retrieves sensitive information or configuration files located in the exposed directories.
7.  The attacker could potentially use the exposed information to further compromise the system.
8.  The final objective is unauthorized access to sensitive data and potentially system compromise.

## Impact

The path traversal vulnerability in pygeoapi allows unauthorized access to directories and files, potentially exposing sensitive data, configuration files, or even source code. The impact depends on the data stored in the exposed directories. Successful exploitation can lead to information disclosure, privilege escalation, and further system compromise. Organizations using vulnerable pygeoapi versions are at risk until they upgrade to version 0.23.3 or implement the recommended workaround.

## Recommendation

*   Upgrade to pygeoapi version 0.23.3 to patch the vulnerability as detailed in the advisory ([https://github.com/advisories/GHSA-f6pr-83pg-ghh6](https://github.com/advisories/GHSA-f6pr-83pg-ghh6)).
*   As an immediate mitigation, disable STAC collection-based resources in the pygeoapi configuration as described in the advisory ([https://github.com/advisories/GHSA-f6pr-83pg-ghh6](https://github.com/advisories/GHSA-f6pr-83pg-ghh6)).
*   Deploy the Sigma rule "pygeoapi Path Traversal Attempt" to detect exploitation attempts in web server logs.
