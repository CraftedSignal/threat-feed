---
title: Signal 'Disappearing' Messages Persist in macOS Notification Center
slug: 2024-01-signal-notification-leak
description: macOS stores Signal message notifications in an unencrypted SQLite database, potentially exposing 'disappearing' messages even after they are deleted from the Signal application.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - macos
  - signal
  - notification
  - privacy
  - credential-access
vendors:
  - Apple
  - Whisper Systems
products:
  - Signal
affected_os:
  - macos
references:
  - https://objective-see.org/blog/blog_0x2E.html
rules:
  - title: Detect Access to macOS Notification Center Database
    description: Detects processes accessing the SQLite database that stores macOS Notification Center data, potentially indicating unauthorized access to sensitive information.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    data_sources:
      - file_event
      - macos
  - title: Detect potential extraction of Notification Data via sqlite3
    description: Detects execution of sqlite3 command line utility to query the notification database
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

A vulnerability exists in the macOS implementation of the Signal messaging application, where 'disappearing' messages may persist in the macOS Notification Center database even after being deleted from the Signal application's user interface. This occurs because Signal posts message content to the Notification Center as a banner notification when the app is not in the foreground. While the OS automatically dismisses these banners, the underlying notification data, including message content, remains stored in an unencrypted SQLite database. This issue affects users of Signal on macOS who rely on the disappearing message feature for privacy. The vulnerability was publicly disclosed in May 2018 by Objective-See.

## Attack Chain

1. A user receives a message in the Signal application on macOS.
2. If the Signal application is not in the foreground, the message content is displayed as a banner notification via the macOS Notification Center.
3. The macOS operating system automatically dismisses the banner notification after a few seconds.
4. The notification data, including the message content, is stored in an SQLite database located at `/private/var/folders/l8/.../com.apple.notificationcenter/db2/db`.
5. The user deletes the message from within the Signal application, triggering its removal from the application's UI.
6. The Signal application does not explicitly remove the corresponding notification from the macOS Notification Center database.
7. An attacker with local access to the macOS system can access the unencrypted SQLite database.
8. The attacker can extract and read the contents of the 'disappearing' messages from the database, bypassing Signal's intended privacy feature.

## Impact

Successful exploitation of this vulnerability allows an attacker with local access to a macOS system to recover and read 'disappearing' messages from the Signal application, even after they have been deleted within the application. This compromises the confidentiality of sensitive communications intended to be ephemeral, potentially impacting a large number of Signal users on macOS.

## Recommendation

*   Enable Sysmon process-creation logging to monitor processes accessing the SQLite database `/private/var/folders/l8/.../com.apple.notificationcenter/db2/db` using the provided Sigma rule.
*   Disable notifications within the Signal application to prevent message content from being stored in the Notification Center database.
*   Consider implementing disk encryption to protect the entire file system, including the Notification Center database.
