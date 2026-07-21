---
title: Multiple High-Severity Vulnerabilities in sharp and libvips Image Processing Libraries
slug: 2026-07-sharp-libvips-vulnerabilities
description: Multiple high-severity vulnerabilities, including CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, and CVE-2026-35591, have been identified and patched in the libvips dependency used by the sharp image processing library, affecting users processing untrusted input with sharp versions prior to 0.35.0 or globally installed libvips prior to 8.18.3.
date: "2026-07-21T22:07:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - supply-chain
  - image-processing
  - npm
  - libvips
vendors:
  - sharp
products:
  - npm/sharp (< 0.35.0)
  - libvips (< 8.18.3)
cves:
  - id: CVE-2026-33327
    epss: 0.00132
  - id: CVE-2026-33328
    epss: 0.0012
  - id: CVE-2026-35590
    epss: 0.0012
  - id: CVE-2026-35591
    epss: 0.00132
references:
  - https://github.com/advisories/GHSA-f88m-g3jw-g9cj
---

Four vulnerabilities, including two rated as "High" severity, have been discovered and subsequently patched in `libvips`, an image processing library, which affects downstream consumers such as the popular Node.js `sharp` package. These vulnerabilities, identified as CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, and CVE-2026-35591, are present in `libvips` versions prior to 8.18.3. Organizations and developers using `sharp` versions older than 0.35.0, or those with a globally installed `libvips` instance prior to 8.18.3, are at risk, particularly if they process untrusted input such as user-supplied image files. Exploitation of these vulnerabilities could lead to denial of service, information disclosure, or potentially arbitrary code execution depending on the specific vulnerability and system configuration, making timely patching critical for maintaining application stability and security.

## Impact

Organizations utilizing the `sharp` library (versions prior to 0.35.0) or `libvips` (versions prior to 8.18.3) for image processing are at risk, particularly if their applications handle untrusted input, such as images uploaded by users. While specific observed exploitation scenarios are not detailed, vulnerabilities in image processing libraries handling untrusted input commonly lead to severe consequences. Successful exploitation could result in denial of service (crashing the application), arbitrary code execution (allowing attackers to run malicious code on the server), or information disclosure, compromising the integrity, availability, and confidentiality of the affected systems and data. All sectors relying on image manipulation services from these libraries, from e-commerce to social media platforms, could be impacted.

## Recommendation

* Upgrade the `sharp` package to version 0.35.3 or later to obtain the patched `libvips` 8.18.3, addressing CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, and CVE-2026-35591.
* If using a globally installed `libvips`, ensure it is updated to version 8.18.3 or newer to mitigate the vulnerabilities.
* Implement the provided code workaround to block decoding of GIF, TIFF, and VIPS images if immediate patching of affected products `sharp (< 0.35.0)` and `libvips (< 8.18.3)` is not possible.
