---
title: CairoSVG Quadratic-Time Denial of Service
slug: 2026-10-cairosvg-dos
description: CairoSVG versions 2.9.0 and earlier are vulnerable to a CPU-exhaustion denial-of-service attack due to O(n²) complexity in SVG path-data parsing and marker rendering.
date: "2026-10-08T19:44:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:cairosvg:cairosvg:*:*:*:*:*:*:*:*
vendors:
  - CairoSVG
products:
  - CairoSVG (<= 2.9.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Rendering an untrusted SVG whose <path d=...> contains many segments is O(n^2) CPU.
    confidence_band: high
cves:
  - id: CVE-2026-107378
references:
  - https://github.com/advisories/GHSA-c3jg-qh8m-j3h2
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107378
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade CairoSVG to 2.9.1 or later
      owner: IT Operations
      due: 48h
      evidence: Source explicitly identifies vulnerability in versions <= 2.9.0.
  mitigation_plan:
    - priority: immediate
      action: Implement length and segment count validation for SVG uploads prior to calling CairoSVG rendering APIs.
      owner: Application Security
      addresses: CVE-2026-107378
      evidence: Source identifies path segment count as the driver for O(n^2) complexity.
---

CairoSVG versions 2.9.0 and earlier contain two independent O(n²) performance bottlenecks that can be exploited by an attacker to conduct a denial-of-service (DoS) attack against applications rendering untrusted SVG documents. The vulnerability exists within `cairosvg/path.py` in the path-data tokenizer and the marker handling logic. The tokenizer consumes path strings using a loop that repeatedly re-slices the remaining string, leading to quadratic time complexity. Simultaneously, the marker rendering function utilizes `list.pop(0)` to drain vertices, which is an O(n) operation in Python, also resulting in O(n²) complexity. 

An attacker can trigger this vulnerability by submitting a specially crafted SVG document with a high density of path segments. Testing demonstrates that a document under 1 MiB can consume approximately 18 seconds of CPU time. This makes any web service that utilizes CairoSVG to process user-supplied SVG files, such as those generating thumbnails, avatars, or PDF exports, highly susceptible to resource exhaustion attacks.

## Impact

The impact of this vulnerability is a high-availability risk for services relying on CairoSVG for image processing. By repeatedly sending these crafted SVG documents, an attacker can effectively pin CPU cores, leading to service degradation or total outage. This affects any application performing server-side rendering of user-provided content.

## Recommendation

1. Upgrade to a version of CairoSVG that includes the fix for CVE-2026-107378. 
2. Implement input validation on the server side to limit the number of segments allowed in a single `<path>` element before processing.
3. Enforce strict timeouts on image rendering jobs to mitigate the impact of CPU-intensive operations on the application server.
