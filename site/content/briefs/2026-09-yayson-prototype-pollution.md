---
title: Prototype Pollution in yayson Store and LegacyStore
slug: 2026-09-yayson-prototype-pollution
description: The yayson library (<= 4.2.0) is vulnerable to prototype pollution when deserializing malicious JSON:API documents, allowing unauthenticated attackers to corrupt the global Object.prototype and potentially achieve RCE via gadget chains.
date: "2026-09-12T00:56:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:yayson_project:yayson:*:*:*:*:*:node.js:*:*
tags:
  - prototype-pollution
  - deserialization
  - remote-code-execution
  - nodejs
products:
  - yayson (<= 4.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The attacker controls the polluted key and value; pollution persists for the process lifetime, enabling logic corruption.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-325j-mg25-8q58
action_plan:
  priority: elevated
  owners:
    - Application Security
    - Development Team
  immediate_actions:
    - action: Upgrade yayson dependency to 4.3.0
      owner: Development Team
      due: 48h
      evidence: Patched in 4.3.0 per GHSA-325j-mg25-8q58
  mitigation_plan:
    - priority: immediate
      action: Enable Node.js flag --disable-proto=throw
      owner: IT Operations
      addresses: CVE-2026-61534
      evidence: Source recommended workarounds
---

The `yayson` library for Node.js contains a critical prototype pollution vulnerability in its `Store` and `LegacyStore` components, tracked as CVE-2026-61534. The library uses incoming JSON:API document fields, specifically `type` and relationship names, as keys for internal lookup tables without proper sanitization. Because these tables are initialized as plain JavaScript objects, an attacker can supply a document where the `type` field is set to `__proto__`. 

This operation writes directly onto the `Object.prototype`, affecting every object within the Node.js process lifetime. The vulnerability is highly impactful as it enables logic corruption or denial of service by design. Furthermore, if the host application contains suitable gadget chains, this pollution can be escalated to arbitrary code execution or authorization bypass. The vulnerability persists even when using `included` resources or custom type mappings, making it difficult to mitigate through standard input validation if the application relies on deeply nested data structures.

## Attack Chain

1. Attacker crafts a malicious JSON:API document containing a `data` object with `type` set to `__proto__`.
2. The target application receives the document via a network request and passes it to the `yayson` `Store.sync()` or `LegacyStore` deserialization method.
3. `yayson` parses the JSON:API object and processes the `type` string as a property key for the internal `models` lookup table.
4. The library performs an assignment operation: `models["__proto__"][id] = model`, which effectively injects properties into the global `Object.prototype` because `__proto__` references the prototype of the `models` object.
5. The attacker includes malicious payloads within the `attributes` or `id` fields of the JSON:API document, which are then persisted globally across the process.
6. The application performs subsequent object operations that trigger the injected malicious properties, leading to code logic alterations or unauthorized state changes.
7. The attacker leverages existing gadget chains in the application environment to execute arbitrary code or bypass security controls based on the polluted prototype properties.

## Impact

The vulnerability allows an unauthenticated attacker to permanently alter the behavior of the Node.js application process. Successful exploitation leads to process-wide logic corruption and denial of service. Depending on the downstream application code, the impact can extend to authorization bypass or full remote code execution. This affects all users of `yayson` versions 3.x and 4.x up to and including 4.2.0.

## Recommendation

Prioritized actions for engineering teams:
- Update the `yayson` library to version 4.3.0 or later to include null-prototype lookup table implementations.
- Implement a temporary mitigation by rejecting incoming JSON documents where `type` or relationship names are set to `__proto__`, `constructor`, or `prototype`.
- Execute Node.js processes with the `--disable-proto=throw` flag to prevent prototype access if the environment permits.
- Audit applications using `yayson` to identify usage of deep object merging or deserialization of untrusted user-supplied JSON:API payloads.
