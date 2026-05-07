---
title: FileBrowser Public Share DELETE API Path Traversal Allows Arbitrary File Deletion
slug: 2026-05-filebrowser-path-traversal
description: A path traversal vulnerability exists in FileBrowser's public share DELETE API allowing unauthenticated attackers with valid share hashes and delete permissions to delete arbitrary files outside the shared directory, leading to unauthorized data loss and potential service disruption.
date: "2026-05-07T03:28:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - file-deletion
  - web-application
vendors:
  - GitHub
products:
  - filebrowser
  - github.com
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-fwj3-42wh-8673
rules:
  - title: Detect FileBrowser Public Share Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability in FileBrowser's public share DELETE API by monitoring for suspicious DELETE requests containing path traversal sequences (../) in the 'path' parameter.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Detect FileBrowser Public Share Path Traversal Attempt (Bulk API)
    description: Detects attempts to exploit the path traversal vulnerability in FileBrowser's public share DELETE API bulk endpoint by monitoring for suspicious DELETE requests with path traversal sequences (../) in the JSON body.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FileBrowser, a web-based file manager, contains a critical path traversal vulnerability in its public share DELETE API. This flaw, present in versions prior to commit 112740bdd41d (May 1, 2026), allows an unauthenticated attacker to delete arbitrary files outside the intended shared directory. The vulnerability stems from insufficient sanitization of the 'path' parameter in the API request. An attacker possessing a valid public share hash with delete permissions enabled can manipulate the 'path' parameter using traversal sequences (e.g., ../) to escape the shared directory and delete files within the share owner's configured storage scope. This issue affects both stable and development versions of FileBrowser, making it a significant risk for users who rely on the public share feature with delete permissions enabled.

## Attack Chain

1. An attacker identifies a FileBrowser instance with public shares enabled and delete permissions granted on at least one share.
2. The attacker obtains a valid public share hash for a specific shared directory.
3. The attacker crafts a malicious DELETE request to the `/public/api/resources` endpoint (for stable versions) or `/public/api/resources/bulk` (for development versions).
4. In the crafted request, the attacker manipulates the `path` parameter (stable) or the `path` field within the JSON body (development) to include path traversal sequences (e.g., `../`).
5. The FileBrowser server receives the request and incorrectly joins the attacker-controlled path with a trusted base path *before* sanitization.
6. Due to the path traversal sequences, the resulting path escapes the intended shared directory.
7. The FileBrowser server attempts to delete the file specified by the manipulated path, which now points to a file outside the intended share.
8. The targeted file is deleted successfully, resulting in unauthorized data loss.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to delete arbitrary files within the share owner's storage scope. This can lead to significant data loss, service disruption, and potential compromise of sensitive information. The impact is particularly severe if the attacker targets critical system files or data repositories accessible within the FileBrowser instance's storage scope. The vulnerability affects FileBrowser instances with public shares and delete permissions enabled, potentially impacting numerous users who rely on this feature.

## Recommendation

*   Apply the patch or upgrade to a version of FileBrowser that includes the fix for CVE-2026-44542 to remediate the path traversal vulnerability.
*   Deploy the Sigma rule "Detect FileBrowser Public Share Path Traversal Attempt" to your SIEM to identify potential exploitation attempts in real-time by monitoring for suspicious DELETE requests with path traversal sequences.
*   Review and restrict the use of public shares with delete permissions enabled to minimize the potential attack surface.
*   Enable webserver logging to provide the necessary data for the provided Sigma rule.
