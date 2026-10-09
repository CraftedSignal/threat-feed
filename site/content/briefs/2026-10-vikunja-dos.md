---
title: Vikunja Unbounded Image Decoding Resource Exhaustion
slug: 2026-10-vikunja-dos
description: Vikunja versions up to 2.5.0 allow denial-of-service attacks by processing maliciously crafted high-aspect-ratio images in avatar and project-background upload endpoints that lack input validation.
date: "2026-10-09T21:24:55Z"
type: advisory
types:
  - advisory
severities:
  - low
cves:
  - id: CVE-2026-91971
    cvss: 6.5
    epss: 0.00436
---

Vikunja versions up to 2.5.0 contain a critical vulnerability in the image processing logic for user avatars and project backgrounds. While the `TaskAttachment` preview functionality includes a 50-megapixel decode guard, the avatar and project-background upload endpoints lack equivalent input validation. An attacker can upload intentionally malformed, extreme-aspect-ratio PNG images that are computationally inexpensive to host but trigger resource exhaustion upon server-side resizing.

The flaw is amplified by the use of `imaging.Resize` with a fixed output height of 1024 pixels. By manipulating the input aspect ratio, an attacker can force the server to allocate massive amounts of memory and CPU cycles to render an output image with dimensions exceeding 2 billion pixels. This vulnerability (CVE-2026-91971) enables a denial-of-service condition where a few-hundred-byte file can cause significant server latency or instability via repeated or concurrent upload requests.

## Attack Chain

1. Attacker identifies the target instance of Vikunja running version 2.5.0 or earlier.
2. Attacker crafts a small PNG file with extreme dimensions (e.g., 20000x10 pixels).
3. Attacker sends a PUT request to the `/api/v1/user/settings/avatar/upload` endpoint containing the crafted image.
4. The application receives the request and initializes the `imaging.Resize` module without an input-side pixel dimension check.
5. The server attempts to resize the image to a fixed height of 1024 pixels while maintaining the extreme aspect ratio.
6. The `imaging` library attempts to allocate memory to process the resulting multi-gigapixel output image.
7. Server CPU and memory consumption spike as the image processing thread handles the excessive pixel data.
8. Repeating this request causes resource exhaustion, resulting in service denial for legitimate users.

## Impact

Successful exploitation results in denial of service (DoS) for the Vikunja instance. The impact is significant for organizations hosting Vikunja as a centralized task management tool, as it renders the application unresponsive or inaccessible. A single attacker can trigger this state using minimal network bandwidth and file storage, making the attack highly efficient and difficult to distinguish from legitimate user activity without specialized request-
