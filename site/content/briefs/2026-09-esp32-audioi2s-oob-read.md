---
title: Heap-based Out-of-Bounds Read in ESP32-audioI2S
slug: 2026-09-esp32-audioi2s-oob-read
description: ESP32-audioI2S versions 3.4.4 through 4.0.0 are susceptible to a heap-based out-of-bounds read vulnerability in the ID3 header parsing logic that could lead to memory disclosure or device instability.
date: "2026-09-10T15:08:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:esp32-audioi2s_project:esp32-audioi2s:*:*:*:*:*:*:*:*
vendors:
  - ESP32-audioI2S
products:
  - ESP32-audioI2S (3.4.4-4.0.0)
cves:
  - id: CVE-2026-87961
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87961
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade ESP32-audioI2S library to version > 4.0.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-87961 advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to IoT audio devices
      owner: Security Operations
      addresses: CVE-2026-87961
      evidence: Source document identifies risk via HTTP audio streams
---

ESP32-audioI2S versions 3.4.4 through 4.0.0 contain a heap-based out-of-bounds read vulnerability in the read_ID3_Header function. The flaw exists due to a shadowed length parameter encountered during the processing of ID3 synchronized-lyrics tags. An attacker can trigger this condition by supplying a malicious MP3 file or a network-delivered HTTP audio stream containing oversized frame size declarations. When the affected library attempts to parse these malformed ID3 tags, it reads beyond the bounds of the allocated heap buffer. Successful exploitation of this vulnerability may result in device crashes (denial of service) or the unauthorized exposure of sensitive data residing in adjacent memory locations. Because this library is commonly used in embedded IoT audio projects, the potential impact involves remote exploitation of internet-connected sound systems and media hardware.

## Impact

Successful exploitation of CVE-2026-87961 leads to denial-of-service via device crash or unauthorized disclosure of adjacent heap memory. Impact is concentrated in IoT environments using ESP32 hardware for audio processing, where devices may be exposed to remote network streams or untrusted file input.

## Recommendation

* Update the ESP32-audioI2S library to a version beyond 4.0.0 that contains the patch for the read_ID3_Header function.
* In environments where immediate patching is not possible, sanitize input audio streams and file uploads to validate ID3 frame size declarations against maximum expected buffer limits.
* Implement network segmentation for IoT devices to restrict access to untrusted HTTP audio sources.
