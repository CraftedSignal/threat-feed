---
title: Gotenberg ExifTool Tag Blocklist Bypass via Group-Prefixed Tag Names
slug: 2026-05-gotenberg-exiftool-bypass
description: Gotenberg is vulnerable to an ExifTool tag blocklist bypass, allowing unauthenticated attackers to rename, move, and modify permissions of files within the container by using group-prefixed tag names like 'System:FileName' or the 'FilePermissions' tag in HTTP requests.
date: "2026-05-04T19:21:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - exiftool
  - file-manipulation
  - cve-2026-40893
vendors:
  - github
products:
  - gotenberg/gotenberg/v8
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/advisories/GHSA-62p3-hvxx-fxg4
rules:
  - title: Detect Gotenberg ExifTool Tag Blocklist Bypass
    description: 'Detects exploitation attempts targeting Gotenberg via ExifTool tag blocklist bypass using System: prefixes in metadata.'
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect Gotenberg FilePermissions Tag Abuse
    description: Detects abuse of the FilePermissions tag in Gotenberg metadata to change file permissions.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Gotenberg, a Docker-based server for document conversion, is susceptible to a critical vulnerability (CVE-2026-40893) that bypasses its intended security measures. Specifically, a blocklist designed to prevent arbitrary file renaming and moving via ExifTool is circumvented by using group-prefixed tag names such as `System:FileName`. This vulnerability, affecting Gotenberg version 8.30.1 and earlier, allows unauthenticated attackers to manipulate files within the container by sending crafted HTTP requests. The bypass allows for renaming files, moving files to arbitrary directories, and changing file permissions, potentially leading to service disruption or, in shared-volume deployments, impacting other services utilizing the same volumes. This vulnerability effectively negates the patch provided in GHSA-qmwh-9m9c-h36m.

## Attack Chain

1.  The attacker identifies a Gotenberg instance (version 8.30.1 or earlier) exposed via HTTP.
2.  The attacker crafts a POST request to any Gotenberg endpoint that accepts the `metadata` field, such as `/forms/pdfengines/metadata/write`, `/forms/chromium/convert/html`, or `/forms/libreoffice/convert`.
3.  The request includes a `files` parameter with a PDF file (or any other supported file type).
4.  The request includes a `metadata` parameter, a JSON object containing malicious ExifTool tag names such as `System:FileName` and `System:Directory`.
5.  Gotenberg's `exiftool.go` validates the tag names against a blocklist but fails to normalize group prefixes, allowing `System:FileName` to bypass the check that would block `FileName`.
6.  ExifTool receives the `System:FileName` and `System:Directory` tags and interprets them as `FileName` and `Directory`, respectively.
7.  ExifTool renames and moves the uploaded file to the attacker-specified location within the container's file system.
8.  If Gotenberg attempts to access the file after it has been moved, the server returns a 404 error, potentially disrupting service for other users.

## Impact

Successful exploitation of this vulnerability (CVE-2026-40893) allows an unauthenticated attacker to manipulate files within the Gotenberg container. This includes the ability to rename files, move them to arbitrary directories, and change their permissions. This can lead to denial-of-service conditions due to missing files, or in scenarios where Gotenberg shares a Docker volume with other services, it allows for planting malicious files in those shared directories. Since no authentication is required by default, any system capable of sending HTTP requests to the Gotenberg instance can exploit this vulnerability, widening the attack surface.

## Recommendation

*   Apply the patch or upgrade to a version of Gotenberg greater than 8.30.1 to remediate CVE-2026-40893.
*   Deploy the Sigma rule `Detect Gotenberg ExifTool Tag Blocklist Bypass` to identify exploitation attempts based on the use of `System:` prefixed ExifTool tags.
*   Deploy the Sigma rule `Detect Gotenberg FilePermissions Tag Abuse` to detect abuse of the `FilePermissions` tag.
*   Monitor webserver logs for POST requests to the affected Gotenberg endpoints (`/forms/pdfengines/metadata/write`, `/forms/chromium/convert/html`, `/forms/libreoffice/convert`) containing the string `System:FileName` or `FilePermissions` in the request body.
