---
title: Integer Overflow in embedded-graphics Library
slug: 2026-09-13-embedded-graphics-integer-overflow
description: An integer overflow vulnerability in the embedded-graphics library (up to version 0.8.2) allows remote attackers to trigger memory corruption via a manipulated width argument in ImageRaw::draw_sub_image.
date: "2026-09-13T21:27:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:embedded-graphics:embedded-graphics:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
vendors:
  - embedded-graphics
products:
  - embedded-graphics (<= 0.8.2)
cves:
  - id: CVE-2026-90593
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90593
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Software Engineering
  immediate_actions:
    - action: Audit codebase for embedded-graphics dependencies.
      owner: Software Engineering
      due: 48h
      evidence: Source document identifies the library and versions affected.
  mitigation_plan:
    - priority: medium_term
      action: Sanitize input width parameters passed to ImageRaw::draw_sub_image.
      owner: Software Engineering
      addresses: CVE-2026-90593
      evidence: Vulnerability originates in ImageRaw::draw_sub_image width argument handling.
  gaps:
    - No fixed version available currently.
---

The embedded-graphics library, widely used in Rust-based embedded systems development, contains an integer overflow vulnerability in the ImageRaw::draw_sub_image function located in src/image/image_raw.rs. This vulnerability affects all versions up to 0.8.2. An attacker can exploit this flaw by providing a specially crafted width argument during the drawing process. This manipulation triggers an integer overflow, which can lead to memory corruption or undefined behavior within the device's memory space. Because this library is commonly used in low-level firmware and embedded display drivers, the scope of impact includes potential crashes or remote code execution depending on the specific integration within the target hardware. As of the report date, the project maintainers have not issued a patch or response to the reported vulnerability.

## Impact

Successful exploitation of this vulnerability in embedded environments can lead to denial-of-service conditions through device crashes or arbitrary code execution. Given the library's role in rendering image data, devices handling untrusted or remote image inputs are at the highest risk of exploitation.

## Recommendation

- Perform an inventory of embedded firmware builds to identify projects utilizing embedded-graphics versions 0.8.2 or older.
- Monitor the official embedded-graphics repository for upcoming security advisories or patch releases addressing CVE-2026-90593.
- If a patch is unavailable, implement input validation logic to sanitize the width argument before it is passed to the ImageRaw::draw_sub_image function to prevent integer overflow conditions.
- Restrict the ability of external or untrusted sources to influence rendering parameters in embedded display applications.
