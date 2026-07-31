---
title: Prototype Pollution in @phun-ky/defaults-deep
slug: 2026-07-phun-ky-prototype-pollution
description: The @phun-ky/defaults-deep library is vulnerable to prototype pollution (CVE-2026-54737) via improper handling of recursive property merging, potentially allowing attackers to modify Object.prototype.
date: "2026-07-31T19:29:20Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - phun-ky
products:
  - defaults-deep
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The library recursively merged user-supplied objects without filtering unsafe property names such as __proto__, constructor, and prototype.
    confidence_band: high
cves:
  - id: CVE-2026-54737
    cvss: 7.3
references:
  - https://github.com/advisories/GHSA-mj3g-7xcc-x4vh
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54737
---

The npm package @phun-ky/defaults-deep is affected by a prototype pollution vulnerability prior to version 2.0.5 (tracked as CVE-2026-54737). The library performs recursive object merging without verifying the presence of dangerous keys such as __proto__, constructor, and prototype. By passing specially crafted, untrusted objects to the defaultsDeep() function, an attacker can influence the behavior of all objects within the Node.js application process. This vulnerability is significant as it can lead to application logic bypasses, denial of service, or, in specific contexts, remote code execution. Defenders should identify applications utilizing this library and prioritize upgrading to version 2.0.5, which includes filters to block the injection of these reserved property names.

## Impact

Successful exploitation allows for the modification of the base Object prototype, which affects all objects across the application's runtime environment. This can result in denial of service by corrupting system functionality, or enable logic bypasses that deviate from expected application code flow. Impact is dependent on the application's specific implementation of objects and how the polluted properties are subsequently accessed or utilized.

## Recommendation

1. Audit dependencies to identify use of @phun-ky/defaults-deep versions earlier than 2.0.5.
2. Upgrade the dependency to version 2.0.5 or later to apply the built-in property filtering.
3. If patching is not immediately feasible, implement input sanitization logic to strip '__proto__', 'constructor', and 'prototype' keys from any untrusted data objects before passing them to the merge function.
