---
title: Prototype Pollution in @toon-format/toon
slug: 2026-09-toon-prototype-pollution
description: The @toon-format/toon library fails to sanitize input, allowing attackers to pollute the Object prototype via __proto__, constructor, or prototype keys, which can lead to denial of service or remote code execution.
date: "2026-09-04T00:07:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:toon-format:toon:*:*:*:*:*:*:*:*
tags:
  - prototype-pollution
  - supply-chain
  - deserialization
vendors:
  - toon-format
products:
  - toon (< 2.3.1)
cves:
  - id: CVE-2026-82404
    cvss: 8.3
references:
  - https://github.com/advisories/GHSA-p95v-992w-h6c3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade @toon-format/toon to 2.3.1
      owner: Development
      due: 72h
      evidence: Patches section of the source advisory
  mitigation_plan:
    - priority: immediate
      action: Implement input validation to block input containing __proto__, constructor, or prototype
      owner: Development
      addresses: CVE-2026-82404
      evidence: Workarounds section of the source advisory
---

The TOON format library, specifically `@toon-format/toon` versions prior to 2.3.1, is vulnerable to prototype pollution when decoding untrusted input. The flaw arises because the library's decoder fails to differentiate between own properties and inherited properties when parsing objects. An attacker supplying input containing `__proto__`, `constructor`, or `prototype` keys can cause the library to write these keys into the JavaScript `Object.prototype`. 

This behavior affects both the `expandPaths: 'safe'` path, which handles dotted keys, and standard nested objects, tabular rows, or quoted keys. Furthermore, the encoder is also defective, silently dropping legitimate own `__proto__` properties and potentially triggering inherited setters during normalization. Successful exploitation allows for the alteration of the runtime environment, which can be leveraged to cause application crashes (denial of service) or, if the application environment contains reachable gadgets, remote code execution. No workarounds exist for this vulnerability; users must upgrade to version 2.3.1 or later.

## Impact

Any service that decodes untrusted TOON input is vulnerable to this prototype pollution attack. Depending on the downstream logic of the host application, this vulnerability can lead to critical security outcomes, including service disruption through denial of service or full system compromise via remote code execution by leveraging gadget chains. The library is commonly used for data interchange, making the scope of potential exploitation wide for any application relying on this package for serialization or deserialization tasks.

## Recommendation

- Upgrade the `@toon-format/toon` package to version 2.3.1 or later to remediate CVE-2026-82404.
- Implement a pre-decoding validation step to inspect input for the presence of '__proto__', 'constructor', or 'prototype' keys if an immediate upgrade is not possible.
- Audit other implementations or language ports of the TOON format (such as those in Rust, Swift, Java, Python, or C#) for similar unsafe object-construction patterns where keys are assigned directly to objects without validation.
