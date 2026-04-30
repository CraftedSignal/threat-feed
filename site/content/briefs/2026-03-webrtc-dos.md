---
title: WebRTC Signaling Denial-of-Service Vulnerability (CVE-2026-4704)
slug: 2026-03-webrtc-dos
description: CVE-2026-4704 is a denial-of-service vulnerability in the WebRTC Signaling component affecting Firefox, Firefox ESR, and Thunderbird, potentially disrupting service availability.
date: "2026-03-24T13:16:06Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - webrtc
  - denial-of-service
  - firefox
  - thunderbird
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4704
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2014868
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-22/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
  - https://www.mozilla.org/security/advisories/mfsa2026-24/
rules:
  - title: Detect Crashes Related to WebRTC Signaling
    description: Detects application crashes potentially related to the WebRTC signaling vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - application
      - windows|linux|macos
  - title: Detect High CPU Usage by Firefox After WebRTC Connection
    description: This rule detects unusual CPU usage by Firefox or Thunderbird after a WebRTC connection, which could indicate a denial-of-service condition due to CVE-2026-4704.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_stats
      - windows|linux|macos
rules_count: 2
---

CVE-2026-4704 is a denial-of-service vulnerability residing in the WebRTC Signaling component of Mozilla products. This flaw impacts Firefox versions prior to 149, Firefox ESR versions before 140.9, Thunderbird versions lower than 149, and Thunderbird also prior to version 140.9. Successful exploitation of this vulnerability could lead to a denial-of-service condition, rendering the affected application unavailable. The vulnerability was disclosed on March 24, 2026. Defenders should prioritize…
