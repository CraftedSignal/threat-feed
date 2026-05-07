---
title: Apple's App Translocation Security Mechanism
slug: 2024-01-app-translocation
description: Apple's App Translocation in macOS v10.12 mitigates Gatekeeper bypasses (CVE-2015-3715, CVE-2015-7024) by creating a read-only DMG, impacting applications accessing external resources.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*
tags:
  - app-translocation
  - gatekeeper
  - macos
  - security-mitigation
vendors:
  - Apple
products:
  - ictool
cves:
  - id: CVE-2015-3715
    epss: 0.0036
  - id: CVE-2015-7024
    cvss: 6.7
    epss: 0.0004
references:
  - https://objective-see.org/blog/blog_0x15.html
rules:
  - title: Detect App Translocation Bypass via File Access
    description: Detects applications attempting to access files within their original download location after being translocated by Gatekeeper, which is indicative of a potential bypass attempt or misconfiguration.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - file_event
      - macos
  - title: Detect App Translocation via Quarantine Attribute
    description: Detects the presence of the com.apple.quarantine extended attribute, indicating a file downloaded from the internet and potentially subject to App Translocation.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - file_event
      - macos
rules_count: 2
---

Apple introduced App Translocation in macOS v10.12 as a response to Gatekeeper bypasses, specifically CVE-2015-3715 and CVE-2015-7024. The core issue was that external content, referenced relatively to a verified application, was not being verified. App Translocation addresses this by creating a read-only DMG image at a randomized location when an application downloaded from the internet is launched. Only the application bundle is included in this DMG. This prevents the application from accessing external resources in the same directory, thus thwarting bypasses that abuse relatively external content. This mechanism relies on the com.apple.quarantine extended attribute to identify downloaded applications. The goal is to generically thwart all Gatekeeper bypasses that abuse relatively external content. This re-architecting of Gatekeeper required changes to numerous OS components and can cause issues for legitimate applications attempting to modify their components post-launch.

## Attack Chain

1.  Attacker crafts a malicious installer package (e.g., ZIP archive or unsigned DMG) containing a signed, Gatekeeper-approved application vulnerable to dylib hijacking.
2.  The package also includes a malicious, unsigned dynamic library (dylib) or executable placed alongside the signed application (e.g., "ibtoold" next to "ictool").
3.  User downloads the malicious package from the internet. The downloaded archive is tagged with the `com.apple.quarantine` extended attribute.
4.  User extracts the application from the downloaded package and double-clicks the signed application to execute it.
5.  App Translocation intercepts the execution attempt and creates a read-only DMG image on the fly, containing *only* the signed application bundle, at a randomized location.
6.  The translocated copy of the application is executed from the read-only DMG.
7.  The signed application attempts to load or execute the external, malicious dylib or executable using a relative path.
8.  Due to App Translocation, the external content is no longer present in the randomized location. The attack fails because the application cannot find the unverified external content.

## Impact

App Translocation was designed to prevent attackers from bypassing Gatekeeper by exploiting signed applications that load external, unvalidated content. Without this mitigation, attackers could execute arbitrary code, potentially leading to malware installation, data theft, or system compromise. The security mechanism has negatively affected legitimate applications that rely on modifying their components or accessing external files in the same directory, requiring developers to find workarounds.

## Recommendation

*   Monitor for the presence of the `com.apple.quarantine` extended attribute on downloaded files to identify applications potentially subject to App Translocation using file_event logs.
*   Deploy the "Detect App Translocation Bypass via File Access" Sigma rule to identify applications attempting to access files in their original download location after being translocated.
*   Audit applications that modify their own binaries or metadata after launch, as App Translocation can prevent these operations. Consider refactoring these applications to comply with App Translocation or explore alternative distribution methods.
*   Consider applications that are affected by App Translocation, potentially breaking auto-update or other legitimate features.
