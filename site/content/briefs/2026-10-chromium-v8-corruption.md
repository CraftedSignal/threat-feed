---
title: Chromium V8 Engine Object Corruption Vulnerability
slug: 2026-10-chromium-v8-corruption
description: CVE-2025-0611 is a high-severity object corruption vulnerability in the Chromium V8 engine that could allow remote arbitrary code execution via a malicious web page.
date: "2026-10-07T17:03:27Z"
lastmod: "2026-10-08T10:50:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:google:chromium:*:*:*:*:*:*:*:*
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - chromium
  - v8
  - browser-security
  - browser
  - cve
vendors:
  - Google
products:
  - Chromium (< 132.0.6834.110)
  - Chromium (< 141.0.7390.54)
cves:
  - id: CVE-2025-0611
    cvss: 8.2
    epss: 0.00415
  - id: CVE-2025-0612
    cvss: 7.5
    epss: 0.00483
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-0612
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-11215
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Patch Chromium to 132.0.6834.110 or later
      owner: IT Operations
      addresses: CVE-2025-0611
      evidence: Microsoft Security Response Center update guide
updates:
  - at: "2026-10-08T10:50:23Z"
    level: L1
    summary: added coverage for Chromium (< 141.0.7390.54)
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-11215
---

CVE-2025-0611 is a high-severity object corruption vulnerability identified within the V8 JavaScript engine used in the Chromium web browser. This flaw exists in the memory management logic of the V8 engine, potentially allowing an attacker to corrupt object structures during execution. If successfully exploited, a remote attacker could influence browser memory, leading to potential arbitrary code execution within the context of the user's browser process. Because Chromium serves as the foundational engine for numerous web browsers and desktop applications, the scope of exposure is significant across all platforms where Chromium-based software is deployed. Defenders should prioritize updating browser versions to the latest patch release provided by their specific vendor to mitigate this risk.

## Impact

Successful exploitation of CVE-2025-0611 allows remote code execution in the context of the browser process. This provides an attacker the ability to bypass standard browser security sandboxes, potentially leading to unauthorized data access, session theft, or the installation of further payloads on the end-user system. The vulnerability affects all users running vulnerable versions of Chromium-based browsers, making it a critical risk for both enterprise environments and general consumer users.

## Recommendation

Prioritize updating all instances of Chromium-based browsers (such as Google Chrome, Microsoft Edge, and Brave) to the latest stable versions that incorporate the upstream fix for CVE-2025-0611. Monitor vendor security update channels for specific release identifiers that address this memory corruption flaw.
