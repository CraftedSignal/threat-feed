---
title: Chromium ANGLE Component Heap Buffer Overflow (CVE-2025-10502)
slug: 2026-10-chromium-angle-overflow
description: CVE-2025-10502 is a heap buffer overflow vulnerability in the Chromium ANGLE graphics engine that could allow an attacker to trigger memory corruption or achieve arbitrary code execution via a malicious webpage.
date: "2026-10-04T04:52:58Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - browser-security
  - remote-code-execution
vendors:
  - Google
products:
  - Chrome (< 140.0.7339.185)
cves:
  - id: CVE-2025-10502
    cvss: 8.8
    epss: 0.00276
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-10502
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Chrome to 140.0.7339.185 or later
      owner: IT Operations
      due: 48h
      evidence: Vendor security guidance necessitates patching to mitigate heap overflow risks.
  mitigation_plan:
    - priority: immediate
      action: Upgrade browser installations to the version containing the fix for CVE-2025-10502
      owner: IT Operations
      addresses: CVE-2025-10502
---

CVE-2025-10502 identifies a heap buffer overflow vulnerability residing within the ANGLE (Almost Native Graphics Layer Engine) component of the Chromium project. ANGLE is used by Chromium-based browsers to translate OpenGL ES calls into underlying graphics APIs such as Direct3D or Metal. This vulnerability is significant because heap buffer overflows in graphics rendering engines often provide a pathway for remote code execution (RCE) if an attacker can successfully manipulate the browser rendering process memory. Because this engine is deeply integrated into the browser's execution pipeline, processing maliciously crafted graphics data can lead to memory corruption, potentially crashing the rendering process or facilitating sandbox escape in specific configurations. Defenders should prioritize updating any Chromium-based applications to the latest security patch provided by the vendor.

## Impact

Successful exploitation of this vulnerability allows an attacker to cause an application crash or potentially execute arbitrary code within the context of the user's browser. If exploited, it could result in full browser compromise, sensitive data exfiltration from the browser's memory space, or further lateral movement into the host system. This vulnerability affects all Chromium-based browsers on Windows, macOS, and Linux platforms.

## Recommendation

Prioritize the deployment of vendor-supplied browser updates across all endpoint assets. Monitor for anomalous browser process crashes or unusual activity emanating from web-rendering sub-processes (often labeled as 'renderer' or 'gpu' processes) which may indicate exploitation attempts.
