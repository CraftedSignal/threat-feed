---
title: scimPatch vulnerable to prototype pollution via unfiltered keys in patch
slug: 2026-07-scimpatch-prototype-pollution
description: The `scim-patch` Node.js library, versions up to and including 0.9.0, is critically vulnerable to prototype pollution (CVE-2026-48170) when processing SCIM PATCH operations, allowing an attacker to modify `Object.prototype` process-wide through crafted `__proto__` keys in the request body, leading to potential privilege escalation or denial of service.
date: "2026-07-03T11:02:23Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - prototype-pollution
  - cve
  - node.js
  - scim
  - critical-vulnerability
vendors:
  - scim-patch
products:
  - scim-patch <= 0.9.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any service that calls `scimPatch()` on attacker-controlled JSON (i.e. any SCIM endpoint accepting `PATCH` from an external IdP) is exploitable on a stock Node runtime.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Privilege escalation if any auth/middleware code checks `actor.isAdmin` / `req.user.admin` / similar boolean flags against a plain object that *expects* the key to be absent.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Application Denial of Service
    evidence: Logic bypass / DoS if any code branches on `obj.name`, `obj.type`, `obj.id` etc. against plain objects (e.g. `pg`'s prepared-statement naming check — a real incident at one consumer).
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-9m6g-wc8r-q59c
  - https://cwe.mitre.org/data/definitions/1321.html
---

The `scim-patch` Node.js library, versions up to and including 0.9.0, is affected by a critical prototype pollution vulnerability, CVE-2026-48170. This flaw allows an unauthenticated or low-privileged attacker to achieve process-wide impact by sending a specially crafted SCIM PATCH request. The delivery mechanism involves a normal SCIM `PATCH /Users/:id` request body where the `value` object contains a key structured as `__proto__.someProp`. When the `scimPatch()` function processes this input, it inadvertently modifies `Object.prototype` in the Node.js runtime. This mutation affects every plain object within the running process, creating a persistent state until the process restarts. For defenders, this is critical because it can lead to severe consequences such as privilege escalation if authentication logic relies on checking properties of otherwise clean objects (e.g., `req.user.isAdmin`), or denial of service through logic bypasses, impacting the availability and integrity of services using `scim-patch`.

## Attack Chain

1.  Attacker crafts a malicious SCIM PATCH request targeting a vulnerable endpoint, for example, `PATCH /Users/:id`.
2.  The request body contains a JSON array with an "add" or "replace" operation, where the `value` object includes a key structured as `__proto__.polluted` or `__proto__.isAdmin`.
3.  The vulnerable Node.js application, using the `scim-patch` library, receives and processes this request via the `scimPatch()` function.
4.  Inside `scimPatch()`, the `addOrReplaceObjectAttribute` function iterates over the user-supplied `patch.value` and feeds the dangerous key (`__proto__.polluted`) to `resolvePaths`.
5.  The `assign` helper function then walks the `keyPath` which includes `__proto__`, and `obj` is reassigned to `Object.prototype` when `obj = obj["__proto__"]` is executed.
6.  Subsequently, the `value` from the malicious patch (e.g., `'yes'` or `true`) is assigned to `Object.prototype.polluted` or `Object.prototype.isAdmin`, effectively polluting the global `Object.prototype`.
7.  This global prototype modification persists until the Node.js process is restarted, affecting all subsequent operations and new objects within that process.
8.  This leads to impacts such as privilege escalation if downstream code checks for properties like `isAdmin` on affected objects, or denial of service through logic bypasses.

## Impact

The impact of CVE-2026-48170 is process-wide, affecting any Node.js service utilizing the `scim-patch` library for SCIM operations. This could include identity management systems, user provisioning services, and enterprise applications that integrate with external Identity Providers (IdPs). If exploited, this prototype pollution can lead to severe consequences such as privilege escalation, enabling attackers to bypass authentication or authorization checks if affected code relies on checking properties of otherwise clean objects (e.g., `req.user.isAdmin`). It can also cause denial of service through logic bypasses if critical application logic branches on object properties, leading to unpredictable behavior or crashes. The modification to `Object.prototype` persists until the Node.js process is restarted, affecting every request handled by the compromised container after pollution, making detection and recovery challenging.

## Recommendation

*   Upgrade the `npm/scim-patch` library to a version beyond `0.9.0` (which includes the fix for CVE-2026-48170) immediately.
*   Implement `Object.freeze(Object.prototype)` at the Node.js process startup to mitigate CVE-2026-48170, as described in the brief's "Mitigation" section.
*   Utilize the Node.js `--frozen-intrinsics` flag during process startup to automatically protect built-in objects from prototype pollution, which helps mitigate CVE-2026-48170.
