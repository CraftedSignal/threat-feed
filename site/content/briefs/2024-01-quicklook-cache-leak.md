---
title: macOS QuickLook Thumbnail Cache Leak
slug: 2024-01-quicklook-cache-leak
description: macOS QuickLook caches thumbnails and file paths of files, even those stored within encrypted containers or on removable USB devices, potentially revealing sensitive data to attackers with access to the running system.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - quicklook
  - cache
  - macos
  - thumbnail
  - privacy
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
references:
  - https://objective-see.org/blog/blog_0x30.html
rules:
  - title: Detect Suspicious QuickLook Cache Access
    description: Detects processes accessing the QuickLook thumbnail cache directory, which could indicate unauthorized data retrieval.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1113
    data_sources:
      - file_event
      - macos
  - title: Detect QuickLook Cache File Access
    description: Detects processes directly accessing QuickLook cache files (index.sqlite, thumbnails.data).
    platform: sigma
    severity: low
    tactics:
      - collection
    techniques:
      - T1113
    data_sources:
      - file_event
      - macos
rules_count: 2
---

The macOS QuickLook feature, designed for quickly previewing file contents, caches thumbnails and file paths of files, including those stored within encrypted containers (e.g., VeraCrypt, macOS Encrypted HFS+/APFS drives) and removable USB devices. This cached information is stored in the clear within the user's temporary directory ($TMPDIR/../C/com.apple.QuickLook.thumbnailcache/) and persists across reboots. This behavior, while known in forensics circles, is not widely understood by Mac users and can lead to unintended data leakage. The file paths, names, and thumbnail previews are accessible to any code running in the context of the user, even after the encrypted container is unmounted or the USB device is removed.

## Attack Chain

1. User mounts an encrypted container (e.g., VeraCrypt, APFS) or inserts a USB drive into a macOS system.
2. User views a directory containing files within the mounted container or USB drive using Finder, or previews a file using the space bar, triggering QuickLook.
3. QuickLook generates thumbnails and caches file paths and names in the `$TMPDIR/../C/com.apple.QuickLook.thumbnailcache/` directory.
4. The `index.sqlite` file stores the file paths and names, while `thumbnails.data` stores the thumbnail images.
5. User unmounts the encrypted container or removes the USB drive.
6. The cached thumbnails and file paths remain in the `$TMPDIR/../C/com.apple.QuickLook.thumbnailcache/` directory.
7. An attacker gains access to the user's macOS system.
8. The attacker extracts the cached thumbnails and file paths from the QuickLook cache directory, potentially revealing sensitive information about the contents of the encrypted container or USB drive.

## Impact

Successful exploitation allows an attacker with access to a macOS system to recover thumbnails and file paths of files that were stored in encrypted containers or on removable USB devices. This can lead to the disclosure of sensitive information, even if the encrypted containers are unmounted or the USB drives are removed. The impact is significant for users who rely on encryption to protect sensitive data, as the QuickLook cache undermines the security provided by encrypted containers. The size of the thumbnails, even the smaller automatically generated ones, may be sufficient to discern the content of the files.

## Recommendation

*   Regularly clear the QuickLook cache, particularly after unmounting encrypted containers. Since `qlmanage -r` doesn't reliably clear the cache, consider deleting the entire `com.apple.QuickLook.thumbnailcache` directory.
*   Implement endpoint detection rules to detect unauthorized access or modification of the QuickLook cache directory (`$TMPDIR/../C/com.apple.QuickLook.thumbnailcache/`) using the "Detect Suspicious QuickLook Cache Access" Sigma rule.
*   Monitor process execution for attempts to access or manipulate the QuickLook cache files (`index.sqlite`, `thumbnails.data`) using the "Detect QuickLook Cache File Access" Sigma rule.
