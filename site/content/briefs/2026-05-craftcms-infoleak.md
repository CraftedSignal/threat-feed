---
title: Craft CMS Missing Volume Permission Check Allows Information Disclosure
slug: 2026-05-craftcms-infoleak
description: Craft CMS versions 5.0.0-RC1 before 5.9.18 are vulnerable to information disclosure where an authenticated control panel user with only accessCp permission can discover filenames and the complete folder structure of assets in unauthorized volumes by supplying arbitrary asset IDs to AssetsController::actionShowInFolder(), exposing sensitive volume structures and enabling targeted follow-up attacks.
date: "2026-05-06T17:54:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - web-application
  - craftcms
vendors:
  - craftcms
products:
  - cms (>= 5.0.0-RC1, < 5.9.18)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
references:
  - https://github.com/advisories/GHSA-33m5-hqp9-97pw
  - https://github.com/craftcms/cms/commit/e3f3eaab3d85badd713cfc2c24e5f0792ecdb586
rules:
  - title: Detect Craft CMS Unauthorized Asset Folder Structure Access
    description: Detects attempts to access the AssetsController::actionShowInFolder endpoint without proper volume permissions, indicating potential information disclosure.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1592.001
    data_sources:
      - webserver
      - linux
  - title: Detect Craft CMS Control Panel Asset Enumeration
    description: Detects access to the AssetsController with requests that might indicate enumeration, even if `show-in-folder` is not directly present.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1592.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Craft CMS versions 5.0.0-RC1 prior to 5.9.18 contain an information disclosure vulnerability in the `AssetsController::actionShowInFolder()` method. This flaw allows any authenticated control panel user, regardless of their volume permissions, to enumerate asset filenames and folder structures of all volumes within the Craft CMS instance. The vulnerability arises from the method fetching asset data and returning its folder hierarchy without properly validating the requesting user's permissions for the asset's volume. This issue was introduced shortly before a patch wave addressing similar vulnerabilities in other `AssetsController` actions, suggesting an oversight in the initial patch implementation. Successful exploitation allows attackers to gain unauthorized insight into sensitive asset organization, which can then be leveraged for subsequent attacks.

## Attack Chain

1. An attacker authenticates to the Craft CMS control panel with minimal permissions (accessCp only).
2. The attacker crafts a malicious request targeting the `AssetsController::actionShowInFolder()` endpoint.
3. The request includes an `assetId` parameter with the ID of an asset residing in a protected volume.
4. The `AssetsController::actionShowInFolder()` method processes the request and fetches the asset information without validating volume-level permissions.
5. The system retrieves the asset's filename and complete folder hierarchy, including volume handle, volume UID, folder names, folder UIDs, and folder URI paths.
6. The asset data is encoded as a JSON response.
7. The JSON response is sent back to the attacker, revealing sensitive structural data about the asset and its parent volume.
8. The attacker gains unauthorized knowledge of asset filenames and folder structures, potentially enabling targeted attacks to access the exposed files.

## Impact

The vulnerability allows any authenticated user with access to the Craft CMS control panel to discover filenames and folder structures of assets in volumes they should not have access to. This exposure of sensitive volume structures, such as private document repositories or confidential media, can lead to unauthorized access to internal files and potentially further compromise of the system. An attacker with knowledge of a private asset's filename and folder path can use this information to launch more targeted attacks, such as attempting to directly access the file through other vulnerabilities or misconfigurations.

## Recommendation

*   Upgrade Craft CMS to version 5.9.18 or later to patch the vulnerability (CVE-2026-44012).
*   Deploy the Sigma rule `Detect Craft CMS Unauthorized Asset Folder Structure Access` to detect unauthorized access attempts to asset folder structures via the `AssetsController::actionShowInFolder` endpoint.
*   Review and enforce strict access control policies within Craft CMS, ensuring that users only have the minimum necessary permissions to access volumes and assets.
