---
title: Heap-based Buffer Overflow in VLC Media Player via Malformed PNG
slug: 2026-09-09-vlc-buffer-overflow
description: A 32-bit integer overflow in VLC media player's picture buffer calculation allows remote attackers to trigger a heap-based buffer overflow via crafted PNG files.
date: "2026-09-09T14:58:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:videolan:vlc_media_player:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - media-player
vendors:
  - VideoLAN
products:
  - VLC media player
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Opening the file directly or through a playlist entry is sufficient, with no non-default settings.
    confidence_band: high
cves:
  - id: CVE-2026-56711
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56711
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Monitor VideoLAN security advisories for the specific patched version of VLC media player
      owner: IT Operations
      addresses: CVE-2026-56711
      evidence: Source documentation of CVE-2026-56711
---

VLC media player is affected by a heap-based buffer overflow vulnerability (CVE-2026-56711) originating in the `AllocatePicture` function within `src/misc/picture.c`. The vulnerability occurs because the application uses 32-bit arithmetic to calculate the size of picture buffers by multiplying `i_pitch` and `i_lines`. Because these fields are declared as `int`, the multiplication wraps before being cast to a 64-bit accumulator. Existing overflow guards use 64-bit division, which fails to constrain the product, and subsequent validation against `PICTURE_SW_SIZE_MAX` checks the already wrapped value. Consequently, `aligned_alloc` reserves an insufficient amount of memory. 

When the PNG decoder (`modules/codec/png.c`) processes a crafted file with large dimensions, it writes scanlines based on the original dimensions into the undersized buffer. This flaw is triggered simply by opening a malicious PNG file or a playlist entry containing a reference to one, without requiring non-default settings. Successful exploitation leads to arbitrary memory corruption, potentially allowing for remote code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to write past the end of an allocated buffer with attacker-influenced data, leading to memory corruption. This poses a high risk to users who open media files from untrusted sources, as the attack requires no user interaction beyond opening the file. The vulnerability affects all versions of VLC media player currently using the vulnerable `AllocatePicture` implementation.

## Recommendation

* Monitor for updates from VideoLAN and patch VLC media player to the version containing the fix for CVE-2026-56711 as soon as it is released.
* Implement endpoint controls to restrict users from opening media files from untrusted network locations or unverified external drives.
* Utilize application control policies to restrict the execution of VLC in high-risk, internet-facing environments if regular patching is not feasible.
