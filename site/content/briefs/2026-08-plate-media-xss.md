---
title: Cross-Site Scripting Vulnerability in Plate Media Embed Renderer
slug: 2026-08-plate-media-xss
description: A vulnerability in the Plate @platejs/media package allows attackers to bypass URL sanitization and achieve Cross-Site Scripting (XSS) by embedding malicious JavaScript URIs in media documents (CVE-2026-55596).
date: "2026-08-25T18:50:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - injection
  - web-application
  - cve-2026-55596
vendors:
  - Plate
products:
  - '@platejs/media'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: A browser proof using the same data flow set an iframe src to javascript:parent.postMessage('plate-media-xss','*') which executed.
    confidence_band: high
cves:
  - id: CVE-2026-55596
    cvss: 8.7
    epss: 0.0043
references:
  - https://github.com/advisories/GHSA-qj6x-xx2h-8hvv
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-55596
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade @platejs/media to 53.1.4
      owner: Application Security
      due: 48h
      evidence: CVE-2026-55596 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Upgrade vulnerable dependency to v53.1.4
      owner: IT Operations
      addresses: CVE-2026-55596
      evidence: Package advisory remediation
---

The Plate media embed component, specifically the `@platejs/media` package (versions 53.0.0 through 53.1.3), contains a critical flaw that allows for Stored Cross-Site Scripting (XSS). The vulnerability exists because the library's `useMediaState` hook contains a fast-path optimization that incorrectly trusts serialized document metadata (`provider`, `sourceUrl`, and `id`) without re-validating the `url` parameter. 

By crafting a Plate document that specifies a legitimate video provider (e.g., `vimeo`) but provides an arbitrary `url` field containing `javascript:` URIs, an attacker can bypass the intended `parseMediaUrl` sanitization logic. When a victim opens a document containing this malicious node, the registry `MediaEmbedElement` trusts the attacker-supplied `provider` metadata and proceeds to render the malicious `url` directly into an `<iframe>` src attribute. This results in the execution of JavaScript within the context of the host application, potentially leading to session hijacking or sensitive data exfiltration.

## Impact

Successful exploitation allows for arbitrary JavaScript execution in the victim's browser context. The impact is dependent on the host application's session model and document access permissions. In collaborative environments, this could lead to widespread XSS against users who view maliciously crafted documents. The vulnerability is addressed in `@platejs/media` version 53.1.4.

## Recommendation

1. Upgrade the `@platejs/media` package to version 53.1.4 or later immediately.
2. Implement strict input validation on the client side to ensure the `url` field in media embeds uses only `http:` or `https:` protocols.
3. Treat all serialized metadata, including `provider`, `sourceUrl`, and `id`, as untrusted; always recompute these values from the `url` field using `parseMediaUrl` rather than relying on cached serialized data.
