---
title: Multiple Vulnerabilities in ImageMagick
slug: 2026-09-imagemagick-vulnerabilities
description: Multiple vulnerabilities in ImageMagick, including CVE-2022-44267 and CVE-2022-44268, allow attackers to trigger denial-of-service, bypass security restrictions, or perform unauthorized disclosure of sensitive information via malformed image files.
date: "2026-09-22T13:57:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*
  - cpe:2.3:a:imagemagick:imagemagick:7.1.0-49:*:*:*:*:*:*:*
vendors:
  - ImageMagick
products:
  - ImageMagick
cves:
  - id: CVE-2022-44267
    cvss: 6.5
    epss: 0.76581
  - id: CVE-2022-44268
    cvss: 6.5
    epss: 0.89855
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3486
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
---

The BSI has released an advisory regarding multiple vulnerabilities in the ImageMagick software suite. These vulnerabilities, identified as CVE-2022-44267 and CVE-2022-44268, affect various implementations of the library. Attackers can leverage these flaws by providing specifically crafted or malformed image files to applications that utilize the ImageMagick engine for image processing. Successful exploitation may allow an unauthenticated attacker to cause a denial-of-service condition through resource exhaustion, bypass intended security controls, or gain unauthorized access to sensitive information stored on the host system. Given that ImageMagick is widely integrated into web applications, content management systems, and backend image-processing pipelines, the impact can be significant for organizations relying on these services. Defenders should prioritize updating ImageMagick to the latest vendor-supplied version to remediate these risks.

## Impact

Successful exploitation of these vulnerabilities can lead to service outages through process crashes or high resource consumption, unauthorized disclosure of local files, and the potential compromise of security restrictions within the application processing the image. These issues affect any system, web server, or desktop application that depends on ImageMagick for handling untrusted image data.

## Recommendation

- Upgrade ImageMagick installations to the latest secure version provided by your distribution or the vendor immediately.
- Audit applications that utilize ImageMagick for image processing to identify potential exposure points to untrusted user-submitted files.
- Implement strict input validation and sandboxing for processes that handle file uploads and image transformation to limit the impact of potential exploitation.
