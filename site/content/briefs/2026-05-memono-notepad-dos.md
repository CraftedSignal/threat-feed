---
title: memono Notepad 4.2 Denial of Service Vulnerability (CVE-2021-47944)
slug: 2026-05-memono-notepad-dos
description: memono Notepad 4.2 is vulnerable to a denial-of-service attack, allowing attackers to crash the application by pasting excessively long character buffers (specifically, two pastes of 350,000 repeated characters) into note fields on iOS devices, as tracked by CVE-2021-47944.
date: "2026-05-10T13:21:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - ios
  - CVE-2021-47944
vendors:
  - memono
products:
  - memono Notepad 4.2
affected_os:
  - iOS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2021-47944
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47944
  - https://www.exploit-db.com/exploits/49977
  - https://www.vulncheck.com/advisories/memono-notepad-denial-of-service-via-buffer-overflow
rules:
  - title: Detect memono Notepad Crash Due to Large Input (CVE-2021-47944)
    description: Detects crashes of memono Notepad on iOS devices, potentially caused by the CVE-2021-47944 vulnerability involving excessive input.
    platform: sigma
    severity: medium
    tactics:
      - availability
      - cve-2021-47944
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - macos
rules_count: 1
---

memono Notepad version 4.2 is susceptible to a denial-of-service (DoS) vulnerability. This flaw allows a remote attacker to crash the application on iOS devices by exploiting its handling of excessively long character buffers within note fields. Specifically, an attacker can trigger this vulnerability by pasting a payload consisting of 350,000 repeated characters twice into a new note. The vulnerability, identified as CVE-2021-47944, could lead to application unavailability and disruption of service for users of the affected application. This vulnerability was reported on May 10, 2026.

## Attack Chain

1.  The attacker crafts a string containing 350,000 repeated characters.
2.  The attacker opens the memono Notepad application on an iOS device.
3.  The attacker creates a new note within the application.
4.  The attacker pastes the crafted string into the note's text field.
5.  The attacker pastes the crafted string a second time into the same note's text field.
6.  The application attempts to allocate memory to handle the oversized buffer.
7.  Due to insufficient memory resources or improper buffer handling, the application crashes.
8.  The user experiences a denial of service as the application becomes unresponsive.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, causing the memono Notepad application to crash on the targeted iOS device. This can lead to data loss if the user has unsaved changes and disrupts the user's ability to take or access notes using the application. While the vulnerability itself doesn't expose sensitive data, repeated exploitation could significantly degrade the user experience and availability of the application. The number of victims is potentially high, given the popularity of note-taking applications on mobile devices.

## Recommendation

*   Monitor process crashes on iOS devices, specifically those originating from memono Notepad, to detect potential exploitation attempts (see the process crash Sigma rule below).
*   Implement application-level input validation to limit the size of text input accepted by memono Notepad to prevent excessively large buffer allocations.
*   Investigate and patch CVE-2021-47944 in memono Notepad to prevent attackers from exploiting this vulnerability.
*   Educate users to avoid pasting untrusted large text payloads into applications on their iOS devices.
