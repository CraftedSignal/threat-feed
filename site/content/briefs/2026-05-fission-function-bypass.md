---
title: Fission Function Invocation Bypass via Public Router Endpoint
slug: 2026-05-fission-function-bypass
description: The Fission router exposes the `/fission-function/<ns>/<name>` endpoint on its public listener, allowing invocation of any function without an HTTPTrigger, leading to unauthorized function access and potential cross-tenant exploitation; patched in v1.23.0.
date: "2026-05-21T20:15:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - fission
  - function-invocation
  - bypass
  - kubernetes
vendors:
  - Fission
products:
  - fission
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-3g33-6vg6-27m8
  - https://github.com/fission/fission/releases/tag/v1.23.0
rules:
  - title: Detect Fission Function Invocation Bypass
    description: Detects CVE-2026-46614 exploitation — HTTP GET request to /fission-function endpoint indicating potential function invocation bypass
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Fission is a Kubernetes-native serverless framework. Versions up to 1.22.0 are vulnerable to a function invocation bypass. The Fission router registered an internal-style route (`/fission-function/<ns>/<name>`) for every Function object, irrespective of any existing HTTPTrigger. This route was exposed on the public listener (svc/router, port 8888). An attacker capable of reaching the router could invoke any function by guessing its `metadata.name` and namespace, thereby circumventing the constraints specified in HTTPTrigger objects, such as host, path, and allowed methods. This vulnerability was patched in version v1.23.0.

## Attack Chain

1. Attacker identifies a Fission deployment with a publicly accessible router (svc/router, port 8888).
2. Attacker enumerates or guesses the `metadata.name` and namespace of Fission functions.
3. Attacker crafts an HTTP GET request to `/fission-function/<ns>/<name>` on the public router endpoint.
4. The Fission router, lacking proper access control, forwards the request to the specified function.
5. The function executes, potentially performing unintended actions or leaking sensitive information.
6. In multi-tenant environments, an attacker in one tenant's pod can invoke functions in another tenant's namespace, crossing tenant boundaries.
7. Attacker bypasses HTTPTrigger-level restrictions (e.g., a function published only on POST /api/v2/foo can be invoked as GET /fission-function/<ns>/<name>).
8. The attacker probes response semantics (404 vs 200 vs 502) to enumerate existing function names.

## Impact

Successful exploitation allows external callers to invoke functions that were not intended for public access, such as internal helpers or sample functions. It also bypasses HTTPTrigger restrictions, enabling invocation of functions with arbitrary headers and bodies. In multi-tenant deployments, this vulnerability can cross tenant boundaries, potentially leading to unauthorized access to sensitive data or resources. Function names can also be enumerated by probing the response semantics, providing attackers with valuable information for further attacks.

## Recommendation

*   Upgrade to Fission v1.23.0 or later to incorporate the fix implemented in PR #3369, which separates public and internal listeners.
*   Apply a NetworkPolicy to the Fission namespace to restrict ingress to `svc/router` (port 8888) only from authorized sources and block access to `/fission-function/...` as suggested in the mitigation steps.
*   If an ingress controller is used, implement path-based filtering at the ingress layer to block access to `/fission-function/` until the upgrade is complete.
*   Deploy the Sigma rule `Detect Fission Function Invocation Bypass` to identify attempts to exploit this vulnerability.
