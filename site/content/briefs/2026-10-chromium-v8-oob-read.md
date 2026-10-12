---
title: Chromium V8 Out-of-Bounds Read Vulnerability (CVE-2025-12441)
slug: 2026-10-chromium-v8-oob-read
description: CVE-2025-12441 is an out-of-bounds read vulnerability in the Chromium V8 JavaScript engine that could potentially lead to sensitive information disclosure within the browser process.
date: "2026-10-12T11:41:59Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
vendors:
  - Google
products:
  - Chromium (unspecified version)
cves:
  - id: CVE-2025-12441
    cvss: 4.3
    epss: 0.00206
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-12441
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Chromium to 142.0.7444.59 or later
      owner: IT Operations
      addresses: CVE-2025-12441
      evidence: Microsoft Security Update Guide advisory for CVE-2025-12441.
---

CVE-2025-12441 is an out-of-bounds read vulnerability identified within the V8 JavaScript engine of the Chromium web browser. This flaw occurs when the engine improperly bounds-checks memory access during script execution. In a browser context, an out-of-bounds read can allow a malicious webpage to access memory regions outside the intended buffer, potentially resulting in the leakage of sensitive data residing in the browser process's memory space. While no specific in-the-wild exploitation was detailed in the MSRC advisory, such vulnerabilities are frequently leveraged by threat actors as a primitive in multi-stage exploit chains to bypass browser sandboxing or facilitate remote code execution when combined with other memory corruption bugs. Defenders should prioritize updating browser environments to the latest patched versions provided by the Chromium project or derivative vendors.

## Impact

Successful exploitation of this vulnerability could lead to unauthorized information disclosure within the context of the browser. Depending on the memory layout and the presence of other security controls, this may expose sensitive data, such as authentication tokens, session identifiers, or other private user information stored in the browser's memory, to a malicious actor controlling the script content.

## Recommendation

* Monitor vendor-specific security update channels for the release of Chromium version 130 or later, which incorporates the fix for CVE-2025-12441.
* Update all instances of Chromium-based browsers (including Google Chrome, Microsoft Edge, and others) as soon as patches are distributed by the respective vendors.
* Utilize browser management policies to enforce timely updates and disable unnecessary JavaScript features in high-security environments.
