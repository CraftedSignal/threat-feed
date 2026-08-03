---
title: CVE-2026-18446 Host Confusion in fast-uri
slug: 2026-08-fast-uri-host-confusion
description: The fast-uri package exhibits a URI parsing discrepancy compared to the native Node.js WHATWG URL parser, allowing attackers to bypass host-based security policies through malicious backslash-encoded authorities.
date: "2026-08-03T20:48:20Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - fast-uri (2.4.4, 3.1.5, 4.1.2)
cves:
  - id: CVE-2026-18446
    cvss: 7.5
    epss: 0.00221
references:
  - https://github.com/advisories/GHSA-7p8r-x3mc-p8w7
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-18446
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Update fast-uri to patched versions
      owner: IT Operations
      due: 48h
      evidence: Upgrade to the patched version.
  mitigation_plan:
    - priority: immediate
      action: Upgrade fast-uri dependency
      owner: IT Operations
      addresses: CVE-2026-18446
      evidence: Upgrade to fast-uri v4.1.2, v3.1.5, v2.4.4.
---

The `fast-uri` package (versions < 2.4.4, 3.0.0-3.1.5, and 4.0.0-4.1.2) is vulnerable to a URI parsing desync (CVE-2026-18446). While Node's native WHATWG `URL` parser treats backslashes as valid authority separators for special schemes like `http` and `https`, `fast-uri` fails to recognize these non-standard authority introducers. 

This inconsistency allows an attacker to supply a URI reference containing backslashes (e.g., `\\evil.com/path`). `fast-uri` treats the sequence as part of the path, causing security validation logic (like SSRF filters or allowlists) to perceive the request as targeting the trusted origin. Conversely, when the downstream `fetch()` or `http` client consumes the same URI, it interprets the sequence as a cross-origin host, effectively bypassing the security controls. This vulnerability is critical for applications that rely on `fast-uri` to perform host-based policy enforcement before passing requests to standard Node.js networking primitives.

## Impact

Successful exploitation allows for the bypass of security controls including SSRF protection, loopback filtering, redirect validation, and outbound proxy routing. If an application uses `fast-uri` to validate an input URL before passing it to `fetch()`, an attacker can reach arbitrary external endpoints, potentially exfiltrating internal data, interacting with internal services, or bypassing egress restrictions.

## Recommendation

* Update the `fast-uri` dependency to versions 2.4.4, 3.1.5, or 4.1.2 immediately to receive the patch.
* Audit applications using `fast-uri` for security validation to ensure they do not perform security-critical decisions on URLs before passing them to native Node.js URL consumers.
* Implement uniform URI parsing throughout the request lifecycle by preferring native Node.js URL APIs if strict `fast-uri` compatibility is not required for performance reasons.
