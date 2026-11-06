---
brief_id: brief-2026-11-05-midnight-blizzard-mobile-watering-hole
event_id: brief-2026-11-05-midnight-blizzard-mobile-watering-hole
revision: 2
activity_at: "2026-11-06T13:10:09Z"
revision_history:
  - revision: 2
    at: "2026-11-06T13:10:09Z"
    checksum: sha256:3ee298385578c3e49f3822e5f91b3c1a912001e5e721d734b9c870df4add4247
    summary: OS ios
    changed_fields:
      - affected_os
      - affected_products
      - iocs
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/apt29-watering-hole-ios-android-n-day-exploits-plerdy
title: 'Midnight Blizzard: Mobile watering hole campaign targeting iOS and Android'
slug: 2026-11-midnight-blizzard-mobile-watering-hole
description: Russian state-sponsored actor Midnight Blizzard (APT29) is leveraging watering holes and lookalike domains to deliver n-day exploit chains against mobile devices.
date: "2026-11-05T11:40:45Z"
lastmod: "2026-11-06T13:09:11Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
actors:
  - APT29
  - Cozy Bear
  - NOBELIUM
  - UNC2452
  - Midnight Blizzard
  - The Dukes
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.securityweek.com/russia-linked-hackers-hit-ios-android-devices-with-exploit-chains-via-watering-holes/
  observed_at: "2026-11-05T00:00:00Z"
  confidence: high
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
cpes:
  - cpe:2.3:a:apple:safari:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:tvos:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:visionos:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:watchos:*:*:*:*:*:*:*:*
  - cpe:2.3:a:webkitgtk:webkitgtk:*:*:*:*:*:*:*:*
  - cpe:2.3:a:wpewebkit:wpe_webkit:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:ipados:26.0:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:iphone_os:26.0:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:macos:26.0:*:*:*:*:*:*:*
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:ar8031_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:csra6620_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:csra6640_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:fastconnect_7800_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:qca2066_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:qca6391_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:qcm6125_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:qcm8550_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:qcn9011_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:qcn9012_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:qcs6125_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:qcs8550_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:video_collaboration_vc1_platform_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:sm6475_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:sm6650_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:sm6650p_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:sm7435_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:sm7635_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:sm7635p_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:qualcomm:smart_audio_400_platform_firmware:-:*:*:*:*:*:*:*
vendors:
  - Apple
  - Google
products:
  - iOS (<= 18.5)
  - Chrome for Android (139 to 145, excluding 143)
  - iOS (16.7)
  - iOS (18.5)
affected_os:
  - iOS 16.7
  - iOS 18.5
  - Android
  - iOS
cves:
  - id: CVE-2025-43529
    cvss: 8.8
    epss: 0.2565
    kev_status: "false"
  - id: CVE-2024-27834
    cvss: 5.5
    epss: 0.01414
    kev_status: "false"
  - id: CVE-2025-43520
    cvss: 5.5
    epss: 0.00425
    kev_status: "false"
  - id: CVE-2026-3910
    cvss: 8.8
    epss: 0.02693
    kev_status: "false"
  - id: CVE-2025-27038
    cvss: 7.5
    epss: 0.01044
    kev_status: "false"
references:
  - https://www.securityweek.com/russia-linked-hackers-hit-ios-android-devices-with-exploit-chains-via-watering-holes/
  - https://pwn.watch/i/apt29-watering-hole-ios-android-n-day-exploits-plerdy
  - https://www.sekoia.com/blog/poisoned-source-apt29-watering-holes-targets-mobile-devices-with-n-day-exploits
iocs:
  - type: domain
    value: a.plerdy.com
ioc_counts:
  domain: 1
updates:
  - at: "2026-11-05T21:31:46Z"
    level: L2
    summary: added CVE-2024-27834 +4; OS ios 18.5; OS android; OS ios 16.7
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/apt29-watering-hole-ios-android-n-day-exploits-plerdy
  - at: "2026-11-06T13:09:11Z"
    level: L1
    summary: OS ios
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/apt29-watering-hole-ios-android-n-day-exploits-plerdy
---

The cybersecurity firm Sekoia reports that the Russian state-sponsored threat actor Midnight Blizzard (APT29) has targeted iOS and Android users in the US and Europe through a large-scale watering hole campaign. 

The campaign involves compromising or cloning high-profile websites to deliver malicious JavaScript that fingerprints visitors. In some instances, the actor utilized adversary-in-the-middle (AiTM) setups with lookalike domains to target high-profile organizations. The campaign relies on n-day exploit chains - utilizing the DarkSword exploit kit for iOS and targeting previously patched vulnerabilities for Android - to exfiltrate device data.
