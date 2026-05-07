---
title: macOS Mojave Sandbox Distributed Notification Bypass
slug: 2024-01-macos-sandbox-leak
description: A vulnerability in macOS Mojave allows sandboxed applications to bypass sandbox restrictions and surreptitiously monitor user activities by registering for distributed notifications by name, circumventing intended privacy protections.
date: "2024-01-26T18:10:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - sandbox-escape
  - privacy
  - macos
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS Mojave
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Defense Evasion
references:
  - https://objective-see.org/blog/blog_0x39.html
rules:
  - title: Detect Sandboxed Application Registering for Distributed Notifications by Name
    description: Detects sandboxed applications registering for specific distributed notifications by name, potentially bypassing sandbox restrictions to monitor user activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - macos
  - title: Detect Process Accessing Distributed Notification Center
    description: Detects processes accessing the Distributed Notification Center which may indicate attempts to monitor system-wide events.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

A vulnerability exists in macOS Mojave that allows sandboxed applications to bypass intended restrictions on distributed notifications. Apple's macOS sandbox aims to prevent malicious applications from spying on users. However, a flaw exists where sandboxed applications can register to receive distributed notifications by name, such as "com.apple.DownloadFileFinished", effectively circumventing the intended restrictions. This vulnerability, disclosed in November 2018, allows a sandboxed application to monitor user activities, such as file downloads, which would normally be prohibited. This affects fully patched macOS Mojave systems and likely other versions of macOS.

## Attack Chain

1.  A malicious application is created and sandboxed on macOS.
2.  The application registers to receive specific distributed notifications by name (e.g., `com.apple.DownloadFileFinished`) using `CFNotificationCenterAddObserver` or `NSDistributedNotificationCenter`.
3.  The sandboxed application monitors system events by receiving distributed notifications.
4.  The application captures user activities, such as file downloads, screen lock/unlock events, screen saver start/stop, and bluetooth activity.
5.  Collected information is stored within the application's sandbox.
6.  The application may then exfiltrate the collected data.
7.  The attacker gains unauthorized access to user activity data, violating user privacy.

## Impact

Successful exploitation of this vulnerability allows sandboxed applications to bypass intended privacy protections and monitor user activities, such as file downloads and system events. This can lead to unauthorized access to sensitive information and a violation of user privacy. While the exact number of victims is unknown, this vulnerability affects any user running a vulnerable version of macOS with a sandboxed application exploiting this flaw.

## Recommendation

*   Monitor process creations for sandboxed applications using `CFNotificationCenterAddObserver` or `NSDistributedNotificationCenter` registering for distributed notifications by name (e.g., `com.apple.DownloadFileFinished`). Deploy the Sigma rule `Detect Sandboxed Application Registering for Distributed Notifications by Name` to your SIEM.
*   Investigate any sandboxed applications that are observed to be receiving distributed notifications using the event names listed in the overview.
*   Consider monitoring network connections made by sandboxed applications to detect potential data exfiltration attempts after gathering notification data.
