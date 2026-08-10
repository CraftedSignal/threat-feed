---
title: Heap Out-of-Bounds Write in GStreamer adpcmdec Element
slug: 2026-08-gstreamer-heap-overflow
description: A heap out-of-bounds write vulnerability in the GStreamer gst-plugins-bad adpcmdec element allows attackers to trigger memory corruption or arbitrary code execution via crafted WAV files.
date: "2026-08-10T03:50:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - memory-corruption
vendors:
  - GStreamer
products:
  - gst-plugins-bad
cves:
  - id: CVE-2026-19387
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19387
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all software using gst-plugins-bad for media processing
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-19387 description
  mitigation_plan:
    - priority: immediate
      action: Patch GStreamer plugins to the latest available version
      owner: IT Operations
      addresses: CVE-2026-19387
      evidence: CVE-2026-19387 remediation requirements
---

A heap out-of-bounds write vulnerability (CVE-2026-19387) has been identified in the GStreamer gst-plugins-bad adpcmdec element. The vulnerability stems from insufficient validation of per-block sample counts when decoding multi-channel IMA/DVI ADPCM audio streams. By supplying a specially crafted WAV file to an application utilizing this GStreamer plugin, an attacker can induce a write operation that exceeds the bounds of the allocated heap output buffer. Depending on the target application's memory layout and GStreamer integration, this flaw may result in process crashes, denial of service, memory corruption, or potentially arbitrary code execution. This issue affects any software package or media player leveraging GStreamer's bad plugins collection for processing untrusted audio input.

## Impact

The vulnerability poses a significant risk to media processing applications across Windows, Linux, and macOS environments that rely on GStreamer plugins. Successful exploitation can lead to a complete compromise of the processing application or a localized denial of service, potentially allowing an attacker to escape sandboxing depending on the privilege level of the media decoding process.

## Recommendation

- Audit systems to identify applications linked against vulnerable versions of the GStreamer gst-plugins-bad package.
- Upgrade to a patched version of GStreamer as provided by your OS distribution or software vendor.
- Apply memory integrity and exploit mitigation features (such as ASLR and DEP) at the OS level to hinder reliable exploitation of heap-based corruption.
- Restrict access to media processing services if they are exposed to untrusted external input until updates are applied.
