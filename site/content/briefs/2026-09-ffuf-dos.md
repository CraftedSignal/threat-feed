---
title: ffuf Denial of Service via Decompression Bomb
slug: 2026-09-ffuf-dos
description: An attacker-controlled server can trigger an out-of-memory denial of service in ffuf (<= 2.1.0) by serving a decompression bomb that bypasses existing size constraints.
date: "2026-09-03T18:04:03Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:ffuf_project:ffuf:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - web-fuzzer
vendors:
  - ffuf
products:
  - ffuf (<= 2.1.0)
cves:
  - id: CVE-2026-73232
    cvss: 7.5
    epss: 0.00441
references:
  - https://github.com/advisories/GHSA-jcvh-xf52-2cwm
  - https://github.com/ffuf/ffuf/pull/897
  - https://github.com/ffuf/ffuf/releases/tag/v2.2.0
action_plan:
  priority: elevated
  owners:
    - Security Research
    - DevOps
  mitigation_plan:
    - priority: immediate
      action: Upgrade all instances of ffuf to version 2.2.0 or later
      owner: DevOps
      addresses: CVE-2026-73232
      evidence: Fixed in ffuf 2.2.0 via https://github.com/ffuf/ffuf/pull/897.
---

The ffuf web fuzzer (versions <= 2.1.0) is susceptible to a denial of service (DoS) vulnerability (CVE-2026-73232) caused by the improper handling of compressed HTTP response bodies. An attacker-controlled server can serve a 'decompression bomb' - a small compressed payload that expands to a significantly larger size upon decompression - causing the ffuf process to exhaust system memory and be terminated by the OS OOM killer. The vulnerability arises because the application's existing response size limit only inspects the 'Content-Length' header of the compressed response. This mechanism is bypassed when using transparent decompression, chunked transfer encoding, or when the 'Content-Length' header represents only the compressed size. The vulnerability forces the process to allocate memory unbounded during the decompression phase, leading to process crashes. This issue was addressed in version 2.2.0 by implementing `io.LimitReader` to enforce a strict 5MB limit on the decompressed response body, regardless of encoding or transport mechanisms.

## Impact

Successful exploitation results in the immediate denial of service of the ffuf scanning process, leading to a loss of in-memory scan results and the inability to interact with the malicious endpoint. This vulnerability poses a risk to security researchers or automated systems utilizing ffuf to scan untrusted or potentially adversarial web infrastructure. The CVSS 3.1 base score is 7.5.

## Recommendation

- Upgrade ffuf to version 2.2.0 or later immediately to incorporate the mandatory `io.LimitReader` boundary.
- Until the upgrade is applied, exercise caution when running ffuf against untrusted or attacker-influenced web targets.
- Monitor host memory usage for processes executing web fuzzing tasks to identify potential OOM-based DoS attempts.
