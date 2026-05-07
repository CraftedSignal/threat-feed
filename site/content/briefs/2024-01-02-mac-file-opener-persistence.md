---
title: Mac File Opener Adware Persists via Document Handler Registration
slug: 2024-01-02-mac-file-opener-persistence
description: The 'Mac File Opener' adware achieves persistence by registering itself as a document handler for numerous file types, leveraging the Launch Services Daemon (lsd) to automatically parse the application's Info.plist and register the handlers.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - adware
  - persistence
  - macos
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://objective-see.org/blog/blog_0x12.html
rules:
  - title: Suspicious Application Execution via Document Handler
    description: Detects the execution of an application from a suspicious location when opening a document file, potentially indicating abuse of document handlers for persistence.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1547.004
    data_sources:
      - process_creation
      - macos
  - title: Suspicious Info.plist Modification for Document Handling
    description: Detects modifications to an application's Info.plist file where a large number of document types are registered, potentially indicating malicious document handler hijacking.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.004
    data_sources:
      - file_event
      - macos
rules_count: 2
---

The 'Mac File Opener' adware, signed with an Apple Developer ID belonging to 'Techyutils Software Private Limited,' is distributed within an 'Advanced Mac Cleaner' installer. This adware distinguishes itself through its persistence mechanism, registering itself as the default 'document handler' for a wide array of file types via its Info.plist file. When a user opens a file without a pre-existing default handler that matches one registered by 'Mac File Opener,' the malware is launched. While this persistence method is less reliable than traditional methods, as it requires user interaction, it effectively bypasses tools that monitor for automatically executed persistence mechanisms. This technique abuses the macOS Launch Services to gain execution.

## Attack Chain

1. User downloads a bundled installer, 'Advanced Mac Cleaner,' containing the 'Mac File Opener' adware.
2. User executes the installer, unknowingly installing the 'Mac File Opener' application.
3. The 'Mac File Opener' application, upon installation, registers itself as a document handler for a wide variety of file types by modifying its Info.plist file.
4. The Launch Services Daemon (lsd) automatically parses the Info.plist file of newly installed applications.
5. Lsd identifies the registered document handlers within 'Mac File Opener's' Info.plist file.
6. Lsd registers 'Mac File Opener' as a handler for the specified file types.
7. User attempts to open a file type that does not have a default application handler, and is handled by 'Mac File Opener.'
8. The OS launches the 'Mac File Opener' application, initiating the adware's malicious activities.

## Impact

The 'Mac File Opener' adware, once launched, can perform various unwanted actions, such as displaying intrusive advertisements, modifying browser settings, or installing additional potentially unwanted programs (PUPs). Although the exact number of victims is unknown, the broad scope of file types targeted suggests a potentially wide impact. Successful exploitation leads to a degraded user experience and potential compromise of system security.

## Recommendation

*   Monitor process creations for the execution of applications from unusual locations (e.g., user's Desktop) when opening document files, using the "Suspicious Application Execution via Document Handler" Sigma rule.
*   Monitor file system events for applications modifying their Info.plist to register a large number of CFBundleTypeExtensions, using the "Suspicious Info.plist Modification for Document Handling" Sigma rule.
*   Regularly audit installed applications and their associated document handlers to identify and remove any suspicious entries.
*   Implement application allowlisting to prevent the execution of unauthorized applications.
