---
title: Craft CMS Vulnerability Allows Low-Privilege Users to Delete Peer Assets
slug: 2026-07-craftcms-peer-asset-deletion
description: A low-privilege user with `deleteAssets` permission in Craft CMS can bypass the `deletePeerAssets` check in the `AssetsController::actionDeleteFolder` function, allowing them to delete assets uploaded by other users (peer assets) within a shared volume, despite lacking the specific `deletePeerAssets` permission, leading to unauthorized data destruction.
date: "2026-07-03T11:48:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - craft-cms
  - vulnerability
  - privilege-escalation
  - data-deletion
  - web-application
vendors:
  - Craft CMS
products:
  - Craft CMS (< 5.9.22)
  - Craft CMS (< 4.17.15)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: A low-privilege user who has been granted folder-management rights on a shared volume can therefore destroy assets uploaded by other users (peer assets), bypassing the per-asset peer-permission check that the sibling `actionDeleteAsset` endpoint correctly applies.
    confidence_band: high
cves:
  - id: CVE-2026-50284
    epss: 0.00249
references:
  - https://github.com/advisories/GHSA-7h62-6v23-v8fm
---

A critical vulnerability (CVE-2026-50284) has been identified in Craft CMS, affecting versions 4.x before 4.17.15 and 5.x before 5.9.22. This flaw, residing in the `AssetsController::actionDeleteFolder` function, allows low-privilege users with `deleteAssets` permission on a shared volume to bypass intended security controls. Specifically, the system fails to enforce `deletePeerAssets` checks when deleting folders, enabling these users to permanently destroy assets uploaded and owned by other users on the same volume. This bypasses Craft CMS's explicit permission model, which aims to distinguish between a user's ability to delete their own assets versus peer-owned assets. The vulnerability can lead to significant data integrity and availability issues, as peer assets can be deleted without recourse through the Craft CMS UI. The issue is similar to a previous fix in `actionMoveFolder` but was not applied to the delete function.

## Attack Chain

1. An administrator grants a low-privilege Craft CMS user `deleteAssets:<volume-uid>` permission for a specific asset volume, but explicitly *does not* grant `deletePeerAssets:<volume-uid>`.
2. The low-privilege user, intending to delete peer-owned assets, sends an authenticated HTTP POST request to the `/admin/assets/delete-folder` endpoint.
3. The request body includes the `folderId` of a folder located within the permitted volume and containing assets uploaded by other users.
4. The `AssetsController::actionDeleteFolder` function executes `requireVolumePermissionByFolder('deleteAssets', $folder)`, which successfully validates the user's `deleteAssets` permission.
5. The function proceeds to call `Assets::deleteFoldersByIds($folderId)`, which iterates through all descendant folders and assets within the target folder.
6. For each identified asset (including peer-owned ones), `Assets::deleteFoldersByIds` directly invokes `Craft::$app->getElements()->deleteElement($asset, true)`.
7. This direct invocation of `deleteElement` bypasses the `Asset::canDelete()` function, which contains the intended `deletePeerAssets` check for individual asset deletions.
8. Consequently, peer-owned assets within the specified folder are permanently removed from the underlying filesystem and become inaccessible via Craft CMS.

## Impact

This vulnerability directly impacts the data integrity and availability of shared asset volumes within Craft CMS environments. Any low-privilege user granted `deleteAssets` permission, without `deletePeerAssets`, can exploit this flaw to permanently destroy files uploaded by other users. This circumvents a fundamental aspect of Craft's permission model, designed to prevent unauthorized deletion of peer data. The consequence is potential data loss and disruption to content operations. While no information disclosure or remote code execution is involved, the inability to distinguish between owned and peer assets for deletion undermines administrative control and can lead to irreversible damage to an organization's digital assets. The impact is broad for any Craft CMS installation utilizing shared asset volumes and differential permissions.

## Recommendation

*   Patch CVE-2026-50284 by upgrading Craft CMS to version 4.17.15 (for 4.x) or 5.9.22 (for 5.x) or higher immediately to remediate the vulnerability.
*   Review all user permissions within Craft CMS, specifically focusing on the `deleteAssets` and `deletePeerAssets` permissions for shared asset volumes, to ensure they align with intended security policies.
