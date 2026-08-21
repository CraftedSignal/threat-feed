---
title: Integer Overflow in GNU Emacs PBM/PPM/PGM Image Loader (CVE-2026-77219)
slug: 2026-08-gnu-emacs-overflow
description: GNU Emacs versions prior to 31.0.91 are susceptible to an integer overflow vulnerability in the PBM/PPM/PGM image loader, potentially leading to heap memory disclosure.
date: "2026-08-21T21:26:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - GNU
products:
  - Emacs
cves:
  - id: CVE-2026-77219
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77219
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Emacs to version 31.0.91 or later to remediate CVE-2026-77219.
      owner: IT Operations
      due: 72h
      evidence: Source advisory recommends version 31.0.91 as the fix.
---

GNU Emacs versions prior to 31.0.91 contain an integer overflow vulnerability within the PBM (Portable Bitmap), PPM (Portable Pixelmap), and PGM (Portable Graymap) image processing logic. The vulnerability arises because the image loader uses signed integer arithmetic to calculate memory allocation sizes based on image dimensions and the maximum color index. By providing a specifically crafted image file containing excessively large dimensions and a manipulated color index value, an attacker can force the multiplication result to wrap to a negative value. This arithmetic error bypasses established bounds checks, resulting in an out-of-bounds heap memory read. When the application attempts to render the pixel data, it processes unintended heap memory contents, which may then be displayed to the user. This vulnerability primarily serves as an information disclosure mechanism, allowing an attacker to leak sensitive heap memory contents if they can trick an Emacs user into opening or rendering a malicious image file.

## Impact

Successful exploitation of this vulnerability results in the unauthorized disclosure of heap memory contents, which could include sensitive data processed by the Emacs instance. While this does not provide direct remote code execution, the disclosure of memory contents could facilitate further exploitation of the application or underlying host. GNU Emacs is widely used across Linux, Windows, and macOS environments, potentially exposing a broad user base to this information leak if they process untrusted PBM/PPM/PGM files.

## Recommendation

1. Upgrade all instances of GNU Emacs to version 31.0.91 or higher, where the integer overflow in the image loader has been remediated.
2. Implement local security policies or email gateway filters to restrict the opening of untrusted PBM, PPM, or PGM image files within GNU Emacs if patching cannot be performed immediately.
3. Validate that existing endpoint detection and response (EDR) solutions are configured to monitor for unusual memory access patterns or unexpected crashes in the Emacs process (emacs.exe or emacs binary).
