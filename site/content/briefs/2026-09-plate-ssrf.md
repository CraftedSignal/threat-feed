---
title: SSRF and Response Disclosure in @platejs/docx-io
slug: 2026-09-plate-ssrf
description: The @platejs/docx-io library is vulnerable to Server-Side Request Forgery (SSRF) and response disclosure, allowing attackers to probe internal networks via malicious HTML image embeddings.
date: "2026-09-03T00:03:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:plate:docx-io:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - ssrf
  - data-exfiltration
vendors:
  - Plate
products:
  - '@platejs/docx-io (< 53.3.2)'
cves:
  - id: CVE-2026-65842
    cvss: 8.2
    epss: 0.00301
references:
  - https://github.com/advisories/GHSA-4q39-2jhr-7qx8
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65842
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @platejs/docx-io to version 53.3.2 or later
      owner: IT Operations
      due: 48h
      evidence: Source explicitly identifies version 53.3.2 as the patch for CVE-2026-65842
  mitigation_plan:
    - priority: immediate
      action: Sanitize HTML input for remote image tags or restrict network access for conversion services
      owner: Security Engineering
      addresses: CVE-2026-65842
      evidence: Source recommends sanitization or environment isolation as a workaround
---

The `@platejs/docx-io` library, versions prior to 53.3.2, contains a vulnerability where the HTML-to-DOCX conversion process insecurely fetches remote image URLs provided in the input HTML. When an application processes untrusted, attacker-controlled HTML in a server-side context, it triggers an outbound HTTP request from the host environment to the URL specified in the HTML. 

This vulnerability (CVE-2026-65842) poses a significant risk for environments where internal network resources are accessible to the server running the conversion. Because the library embeds the fetched image data into the generated DOCX file, an attacker can leverage this mechanism to exfiltrate data from otherwise unreachable internal services or probe for open ports and services, resulting in a server-side response disclosure. Defenders should ensure all input is sanitized or processed in a network-isolated environment.

## Impact

The vulnerability affects applications that utilize `@platejs/docx-io` to convert untrusted HTML into DOCX files, particularly in server-side workflows. Successful exploitation enables unauthorized internal network probing and potential leakage of sensitive internal data into the exported document. All users are urged to upgrade to version 53.3.2 or later to mitigate the risk.

## Recommendation

- Upgrade the `@platejs/docx-io` package to version 53.3.2 or later immediately to patch CVE-2026-65842.
- Implement strict input sanitization on all user-supplied HTML before it reaches the conversion engine to strip remote image source references.
- Convert any necessary remote images into Base64-encoded Data URIs within the application layer prior to calling the library for DOCX conversion.
- Isolate the conversion process within a sandboxed environment or a container with egress-restricted network access to prevent unauthorized outbound requests.
