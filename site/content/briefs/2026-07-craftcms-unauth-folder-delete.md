---
title: Craft CMS Vulnerable to Unauthorized Folder Deletion (CVE-2026-50282)
slug: 2026-07-craftcms-unauth-folder-delete
description: A high-severity vulnerability (CVE-2026-50282) in Craft CMS allows an authenticated user to delete destination folders and their contents without explicit delete permissions during a forced folder move operation, enabling asset loss, breaking existing asset references, and causing operational disruption.
date: "2026-07-03T11:30:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - cms
  - craft-cms
  - webserver
  - cve
vendors:
  - Craft CMS
products:
  - Craft CMS (>= 5.0.0-RC1, < 5.9.21)
  - Craft CMS (>= 4.0.0-RC1, < 4.17.14)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Data Destruction
    evidence: A user who cannot delete assets in a destination volume can still delete a destination folder and its contents by triggering a forced move into a conflicting name. This can cause asset loss, broken references in entries and fields that point to deleted assets, and operational disruption.
    confidence_band: high
cves:
  - id: CVE-2026-50282
references:
  - https://github.com/advisories/GHSA-3w32-23wj-rxg3
---

A high-severity vulnerability (CVE-2026-50282) has been identified in Craft CMS versions 4.x and 5.x, where an authenticated user can perform unauthorized deletion of destination folders during a forced move operation. Specifically, Craft CMS versions `5.0.0-RC1` through `5.9.20` and `4.0.0-RC1` through `4.17.13` are affected. The flaw resides in `craft\controllers\AssetsController::actionMoveFolder()`, which permits a folder to be overwritten at the destination if `force=true` is used, without properly verifying `deleteAssets` permission for the destination volume. This oversight allows an attacker with legitimate access but lacking explicit delete privileges to eliminate arbitrary destination folders and their contents, leading to data loss, broken asset references within entries and fields, and significant operational disruption for affected organizations utilizing Craft CMS.

## Attack Chain

1.  An authenticated attacker logs into the Craft CMS administrative interface.
2.  The attacker identifies an existing asset folder, `MaliciousFolder`, and a target destination parent folder, `TargetDestination`, where another legitimate folder (`VictimFolder`) with the same name as `MaliciousFolder` already exists.
3.  The attacker prepares a move operation for `MaliciousFolder` into `TargetDestination`.
4.  The attacker crafts a request to `craft\controllers\AssetsController::actionMoveFolder()` specifying `MaliciousFolder` as the source, `TargetDestination` as the destination, and includes the `force=true` parameter.
5.  Despite the attacker lacking `deleteAssets` permission for the volume containing `VictimFolder` within `TargetDestination`, the Craft CMS application logic proceeds.
6.  The application detects the name conflict and, due to the `force=true` parameter, initiates the deletion of `VictimFolder` and all its contents using `assets->deleteFoldersByIds($existingFolder->id)` or `targetVolume->deleteDirectory()`.
7.  Subsequently, `MaliciousFolder` is moved into `TargetDestination`.
8.  The unauthorized deletion of `VictimFolder` results in data loss, broken asset references in site content, and operational disruption.

## Impact

This vulnerability allows an authenticated user, even without explicit delete permissions on the destination volume, to force the deletion of folders and their contents. The direct consequence is asset loss, potentially affecting critical site content and media. This can lead to broken references throughout the Craft CMS instance, rendering parts of the website non-functional or displaying incorrect information. Organizations using affected versions of Craft CMS could face significant operational disruption, data recovery efforts, and reputational damage due to the loss of digital assets.

## Recommendation

*   Immediately apply available patches for Craft CMS, upgrading affected installations to versions `5.9.21` or `4.17.14` or later to remediate CVE-2026-50282.
*   Review and strictly enforce user role permissions within Craft CMS, particularly for `deleteAssets` and `createFolders` on asset volumes, as this vulnerability allows an authorization bypass related to these.
*   Ensure comprehensive web server access logging is enabled for your Craft CMS instance. Specifically, monitor for `POST` requests to `/admin/actions/assets/move-folder` that include the `force=true` parameter, especially when originating from user accounts with limited asset management privileges.
