---
brief_id: brief-2026-11-google-security-updates
event_id: brief-2026-11-google-security-updates
revision: 1
activity_at: "2026-11-02T17:54:57Z"
title: Google Security Updates - November 2026
slug: 2026-11-google-security-updates
description: Roundup of Google security advisories published in November 2026.
date: "2026-11-02T17:54:57Z"
lastmod: "2026-11-04T00:26:13Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - roundup
vendors:
  - Google
cves:
  - id: CVE-2026-105769
    cvss: 9.3
    kev_status: "false"
  - id: CVE-2026-121034
    cvss: 9.6
    kev_status: "false"
  - id: CVE-2026-121035
    kev_status: unknown
  - id: CVE-2026-28588
    kev_status: unknown
  - id: CVE-2026-28597
    kev_status: unknown
  - id: CVE-2026-45514
    kev_status: unknown
  - id: CVE-2026-49922
    kev_status: unknown
  - id: CVE-2026-49923
    kev_status: unknown
  - id: CVE-2026-49931
    kev_status: unknown
  - id: CVE-2026-55257
    kev_status: unknown
  - id: CVE-2026-55287
    kev_status: unknown
  - id: CVE-2026-58836
    kev_status: unknown
  - id: CVE-2026-58837
    kev_status: unknown
  - id: CVE-2026-58866
    kev_status: unknown
  - id: CVE-2026-58884
    kev_status: unknown
  - id: CVE-2026-58943
    kev_status: unknown
  - id: CVE-2026-58944
    kev_status: unknown
  - id: CVE-2026-58946
    kev_status: unknown
  - id: CVE-2026-58957
    kev_status: unknown
  - id: CVE-2026-58965
    kev_status: unknown
  - id: CVE-2026-58970
    kev_status: unknown
  - id: CVE-2026-55262
    kev_status: unknown
  - id: CVE-2026-121030
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121035
updates:
  - at: "2026-11-02T17:54:57Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-105769
  - at: "2026-11-04T00:26:13Z"
    level: L2
    summary: added CVE-2026-121034
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121035
---

This roundup covers 22 Google security vulnerabilities. All have a CVSS base score of 9.3. None are reported as actively exploited at the time of release. The issues affect Android, Chrome.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-105769](#cve-2026-105769) | n/a | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-105769) (authoritative) |
| [CVE-2026-28588](#cve-2026-28588) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-28588) (authoritative) |
| [CVE-2026-28597](#cve-2026-28597) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-28597) (authoritative) |
| [CVE-2026-45514](#cve-2026-45514) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-45514) (authoritative) |
| [CVE-2026-49922](#cve-2026-49922) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-49922) (authoritative) |
| [CVE-2026-49923](#cve-2026-49923) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-49923) (authoritative) |
| [CVE-2026-49931](#cve-2026-49931) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-49931) (authoritative) |
| [CVE-2026-55257](#cve-2026-55257) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-55257) (authoritative) |
| [CVE-2026-55287](#cve-2026-55287) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-55287) (authoritative) |
| [CVE-2026-58836](#cve-2026-58836) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58836) (authoritative) |
| [CVE-2026-58837](#cve-2026-58837) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58837) (authoritative) |
| [CVE-2026-58866](#cve-2026-58866) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58866) (authoritative) |
| [CVE-2026-58884](#cve-2026-58884) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58884) (authoritative) |
| [CVE-2026-58943](#cve-2026-58943) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58943) (authoritative) |
| [CVE-2026-58944](#cve-2026-58944) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58944) (authoritative) |
| [CVE-2026-58946](#cve-2026-58946) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58946) (authoritative) |
| [CVE-2026-58957](#cve-2026-58957) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58957) (authoritative) |
| [CVE-2026-58965](#cve-2026-58965) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58965) (authoritative) |
| [CVE-2026-58970](#cve-2026-58970) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58970) (authoritative) |
| [CVE-2026-55262](#cve-2026-55262) | Android |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-55262) (authoritative) |
| [CVE-2026-121030](#cve-2026-121030) | Chrome (< 157.0.8103.38) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121030) (authoritative) |
| [CVE-2026-121034](#cve-2026-121034) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121034) (authoritative) |


## CVE-2026-105769

A vulnerability exists in kaniko versions prior to 1.25.20 due to the improper use of the Azure Container Registry credential helper. The helper uses an unanchored regex to validate hostnames, allowing an attacker to supply a lookalike domain (e.g., x.azurecr.io.attacker.com) to trigger the tool into sending the build environment's Microsoft Entra ID access token to an attacker-controlled endpoint. This allows for unauthorized token exfiltration and potential downstream access to Azure resources.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-105769

## CVE-2026-28588

CVE-2026-28588 describes a logic error in the shouldBlockDirectoryFromTree function within ExternalStorageProvider.java of the Android operating system. This vulnerability allows an attacker to bypass directory protection mechanisms and gain unauthorized access to protected data, resulting in local privilege escalation without the need for additional execution privileges or user interaction.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-28588




















Related in this roundup: [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-28597

CVE-2026-28597 describes a vulnerability in UriGrantsManagerService.java within the Android platform where improper input validation in writeGrantedUriPermissions enables a local privilege escalation. An attacker can exploit this flaw without user interaction or elevated execution privileges to gain unauthorized access to URI permissions.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-28597




















Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-45514

A logic error within the SaveUi.java component of the Android operating system allows an attacker to bypass package installation requirements. This vulnerability permits local privilege escalation without requiring user interaction or elevated execution privileges.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-45514



















Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-49922

CVE-2026-49922 describes a local privilege escalation vulnerability in ConnectionServiceWrapper.java due to a confused deputy issue within queryRemoteConnectionServices. The vulnerability allows an attacker to bypass permission checks, facilitating unauthorized access or escalation without requiring additional execution privileges or user interaction.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-49922


















Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-49923

A logic error in the AccountManagerService.java component of the Android framework within the onResult method allows for a local privilege escalation. The vulnerability enables a local attacker to perform unauthorized actions by presenting misleading UI elements, bypassing the need for additional execution privileges or user interaction.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-49923

















Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-49931

CVE-2026-49931 describes a vulnerability in Android's onActivityResult handling where a confused deputy flaw allows for unauthorized access to contact information from a protected profile. This local escalation of privilege vulnerability does not require user interaction or additional execution privileges to exploit.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-49931
















Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-55257

A vulnerability in UsbDialogHelper.java within the Android USB dialog handling mechanism allows for local privilege escalation. The flaw stems from insufficient or misleading UI, enabling an attacker to escalate privileges without requiring user interaction or elevated execution permissions.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-55257















Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-55287

CVE-2026-55287 is a privilege escalation vulnerability within the GrantCredentialsPermissionActivity.java component of the Android operating system. A vulnerability in the onCreate method allows an attacker to deceive a user into granting unauthorized access to account credentials through a misleading or insufficient user interface. The vulnerability does not require additional execution privileges or user interaction, potentially allowing for local privilege escalation.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-55287














Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-58836

A logic error in InstallPackageHelper.java within the Android framework's handlePackagePostInstall method allows a sideloaded application to bypass Enhanced Confirmation Mode (ECM) restrictions during self-updates. This vulnerability enables a local attacker to perform privilege escalation on the affected system, leveraging existing user-level execution privileges to modify the package source.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58836













Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-58837

CVE-2026-58837 describes a vulnerability involving a logic error that allows for unauthorized background activity launches. This flaw can be leveraged for local privilege escalation without requiring user interaction or elevated execution privileges.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58837












Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-58866

A vulnerability in AccessibilityWindowManager.java within the Android framework allows for local privilege escalation due to a missing permission check in setAccessibilityWindowAttributes. This flaw enables a local attacker to present misleading UI components without requiring user interaction or elevated privileges, potentially leading to unauthorized actions or data access.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58866











Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-58884

A vulnerability in WifiServiceImpl.java's startTetheredHotspotRequest method allows for a confused deputy attack, enabling a local attacker to escalate their privileges without requiring additional permissions or user interaction.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58884










Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-58943

A vulnerability exists in AddAccountSettings.java where a confused deputy flaw allows for unauthorized background activity launches. This issue permits local privilege escalation without requiring additional execution privileges or user interaction, posing a significant risk to the affected system's security integrity.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58943









Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-58944

CVE-2026-58944 describes a vulnerability in ActivityTaskManagerService.java involving a background application launch (BAL) issue caused by a confused deputy condition. This flaw allows a local attacker to achieve privilege escalation without requiring special execution permissions or user interaction.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58944








Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-58946

A vulnerability in ActivityClientController.java within the Android framework allows a local user to bypass permission checks via a logic error in navigateUpTo. This flaw enables local privilege escalation without requiring additional execution privileges or user interaction, resulting in a CVSS v3.1 base score of 8.4.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58946







Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-58957

CVE-2026-58957 is a local privilege escalation vulnerability in the Android ActivityStarter component. A confused deputy issue within the resolveToHeavyWeightSwitcherIfNeeded method allows for unauthorized background activity launches without user interaction or elevated execution privileges.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58957






Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-58965

CVE-2026-58965 describes a vulnerability in the handleAudioEffectBroadcast method within MusicFxHelper.java on the Android platform. The issue arises from a confused deputy condition, allowing an attacker to bypass permission checks. This vulnerability facilitates local privilege escalation without requiring user interaction or elevated execution privileges.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58965





Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58970](#cve-2026-58970), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-58970

A vulnerability in AppTimeTracker.java allows a confused deputy attack, enabling local privilege escalation without user interaction or special execution privileges.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58970




Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-55262](#cve-2026-55262).

## CVE-2026-55262

CVE-2026-55262 involves a policy desynchronization flaw within the NotificationManagerService of the Android operating system. The vulnerability stems from improper input validation in the setNotificationListenerAccessGrantedForUserInternal function, enabling a local attacker to escalate privileges without requiring additional execution privileges or user interaction.

Affected products:
- Android

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-55262



Related in this roundup: [CVE-2026-28588](#cve-2026-28588), [CVE-2026-28597](#cve-2026-28597), [CVE-2026-45514](#cve-2026-45514), [CVE-2026-49922](#cve-2026-49922), [CVE-2026-49923](#cve-2026-49923), [CVE-2026-49931](#cve-2026-49931), [CVE-2026-55257](#cve-2026-55257), [CVE-2026-55287](#cve-2026-55287), [CVE-2026-58836](#cve-2026-58836), [CVE-2026-58837](#cve-2026-58837), [CVE-2026-58866](#cve-2026-58866), [CVE-2026-58884](#cve-2026-58884), [CVE-2026-58943](#cve-2026-58943), [CVE-2026-58944](#cve-2026-58944), [CVE-2026-58946](#cve-2026-58946), [CVE-2026-58957](#cve-2026-58957), [CVE-2026-58965](#cve-2026-58965), [CVE-2026-58970](#cve-2026-58970).

## CVE-2026-121030

An incorrect authorization vulnerability in the DevTools component of Google Chrome prior to version 157.0.8103.38 could allow a remote attacker to achieve arbitrary code execution outside the browser sandbox. The attack requires user interaction through social engineering, specifically enticing a user to navigate to a crafted HTML page.

Affected products:
- Chrome (< 157.0.8103.38)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121030

## CVE-2026-121034

A use-after-free vulnerability exists in the Views component of Google Chrome on Windows versions prior to 157.0.8103.38. This flaw allows a remote attacker to execute arbitrary code outside the browser sandbox by tricking a user into navigating to a crafted HTML page through social engineering.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121034
