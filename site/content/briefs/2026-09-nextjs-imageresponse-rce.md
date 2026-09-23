---
title: Critical RCE Vulnerability in Next.js ImageResponse via Crafted SVG Input
slug: 2026-09-nextjs-imageresponse-rce
description: A critical vulnerability (CVE-2026-94545) in the Next.js ImageResponse feature allows unauthenticated remote code execution when attacker-controlled input is improperly sanitized during SVG generation.
date: "2026-09-23T07:52:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-vulnerability
  - rce
  - server-side
  - nextjs
vendors:
  - Vercel
products:
  - Next.js (16.2.0-16.3.5)
  - Satori (< 0.33.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A new security vulnerability in Next.js could allow attackers to run code on a server via ImageResponse.
    confidence_band: high
references:
  - https://thehackernews.com/2026/09/critical-nextjs-imageresponse-flaw-can.html
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Development Team
  immediate_actions:
    - action: Upgrade Next.js to 16.3.6 or higher across all production environments.
      owner: Development Team
      due: 24h
      evidence: The fix is Next.js 16.3.6, the only patched version.
  mitigation_plan:
    - priority: immediate
      action: Remove attacker-controlled input from SVG content, attributes, and styles passed to ImageResponse.
      owner: Development Team
      addresses: CVE-2026-94545
      evidence: The advisory's workaround is to keep attacker-controlled values out of the SVG content.
---

Vercel has disclosed a critical security vulnerability, tracked as CVE-2026-94545, affecting the ImageResponse feature in Next.js versions 16.2.0 through 16.3.5. The flaw originates in the underlying Satori library, which converts image layouts into SVG code. When applications pass attacker-controlled values, such as those derived from request URLs, into SVG content, attributes, or styles, the lack of proper sanitization allows the input to be interpreted as malicious SVG markup. 

This flaw is particularly dangerous when the ImageResponse runs on the default Node.js runtime, as the processed malicious markup can trigger further vulnerabilities in downstream library dependencies, leading to remote code execution (RCE). Next.js 16.3.6 and Satori 0.33.5 include the necessary fixes to properly escape user-provided content. While no public exploits have been reported, the vulnerability affects any application that dynamically generates Open Graph or social preview images based on user input.

## Impact

Successful exploitation allows an unauthenticated remote attacker to achieve code execution on the server hosting the Next.js application. Given that ImageResponse is frequently used for dynamic social media preview generation, high-traffic applications are at significant risk of compromise. The vulnerability has a CVSS score of 9.5, reflecting its potential for full system compromise. 

## Recommendation

Prioritize the following actions to mitigate the risk posed by CVE-2026-94545:

- Upgrade all Next.js deployments running affected versions (16.2.0 through 16.3.5) to Next.js 16.3.6 immediately.
- If the application uses the Satori library directly, update the dependency to version 0.33.5 or later.
- Audit all route handlers and opengraph-image files to identify instances where user-supplied input (e.g., from query parameters or headers) is passed into ImageResponse components.
- Implement strict input validation and sanitization for any user-controlled values intended for use in image generation as a temporary defense-in-depth measure.
