---
title: Grav CMS Path Traversal in MediaUploadTrait Leading to Arbitrary File Deletion
slug: 2026-09-grav-path-traversal
description: An authenticated path traversal vulnerability in Grav CMS's MediaUploadTrait allows users with media management permissions to delete arbitrary files on the server by providing crafted file paths.
date: "2026-09-18T01:11:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:grav:*:*:*:*:*:*:*:*
tags:
  - grav
  - cms
  - path-traversal
  - cve-2026-72695
vendors:
  - GetGrav
products:
  - Grav CMS (<= 2.0.15)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack requires an authenticated admin user with page/media editing permissions (not super-admin).
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: An authenticated user with media management permissions can delete arbitrary files on the server.
    confidence_band: high
cves:
  - id: CVE-2026-72695
    cvss: 8.1
    epss: 0.00567
references:
  - https://github.com/advisories/GHSA-jq29-c7v8-rg55
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Grav CMS to 2.0.16 or later
      owner: IT Operations
      due: 24h
      evidence: Source provides explicit patched version requirement
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the admin interface to trusted IP ranges
      owner: IT Operations
      addresses: CVE-2026-72695
      evidence: Attack requires authenticated session
---

Grav CMS versions 2.0.15 and earlier are vulnerable to a path traversal vulnerability in the `MediaUploadTrait::deleteFile()` method within `system/src/Grav/Common/Media/Traits/MediaUploadTrait.php`. The vulnerability arises because the application only performs filename validation on the basename using `Utils::checkFilename()` while failing to sanitize the directory path component. An authenticated user with media management permissions can exploit this by submitting specially crafted filenames containing directory traversal sequences (e.g., `../`). When passed to the `doRemove()` method, these sequences allow the application to bypass directory restrictions and invoke `unlink()` on files located outside the intended media storage path. This vulnerability can be used to cause a denial of service by deleting critical system configurations, application logic, or authentication-related files, potentially resulting in privilege escalation or complete system disruption.

## Attack Chain

1. An authenticated attacker with page or media editing permissions initiates a request to the Grav CMS admin interface.
2. The attacker triggers a Flex media handling operation, such as editing a page, that allows media deletion.
3. The attacker intercepts or crafts a POST request to the `/admin/pages/[page]/task:save` endpoint.
4. The request payload is modified to include a media deletion marker with a key containing path traversal sequences (e.g., `../../data/target.txt`).
5. The application’s `FlexMediaTrait::saveUpdatedMedia()` method processes the deletion queue, passing the unsanitized traversal string to `deleteFile()`.
6. The `deleteFile()` method validates only the basename (e.g., `target.txt`), which passes the `Utils::checkFilename()` filter despite the malicious directory prefix.
7. The `doRemove()` method concatenates the path and invokes the PHP `unlink()` function on the resolved path.
8. The underlying filesystem executes the deletion of the target file, outside the authorized media directory.

## Impact

Successful exploitation allows an authenticated user to delete critical application files, including configuration files such as `user/config/system.yaml` or `user/config/security.yaml`, and user account files. This leads to immediate denial of service or potential privilege escalation by removing security restrictions. The impact is significant for environments where untrusted users are granted administrative-level media management access.

## Recommendation

1. Update Grav CMS to the version containing the patch for CVE-2026-72695 immediately.
2. Implement a custom validation logic for the `MediaUploadTrait` that applies `Utils::checkFilename()` to the entire file path, as documented in the provided fix.
3. Audit administrative permissions and restrict media management access to strictly vetted users.
4. Monitor web server logs for HTTP POST requests to `/admin/pages/` containing path traversal characters like `../` or `..%2f` within the payload.
