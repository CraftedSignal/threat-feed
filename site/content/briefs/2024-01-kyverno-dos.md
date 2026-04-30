---
title: Kyverno Controller Denial of Service via forEach Mutation Panic
slug: 2024-01-kyverno-dos
description: An unchecked type assertion in Kyverno versions v1.13.0 to v1.17.1 allows a user with permission to create a Policy or ClusterPolicy to crash the cluster-wide background controller into a persistent CrashLoopBackOff, leading to a denial of service, by crafting a malicious policy that triggers a nil pointer dereference in the forEach mutation handler.
date: "2024-01-27T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kyverno
  - denial-of-service
  - kubernetes
  - policy-engine
vendors:
  - Kyverno
products:
  - Kyverno
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Replication Through Removable Media
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-fpjq-c37h-cqcv
rules:
  - title: Detect Kyverno Policy with Suspicious forEach
    description: Detects Kyverno policies containing a forEach loop and patchesJson6902, which may be indicative of a crafted policy designed to trigger a denial-of-service.
    platform: sigma
    severity: medium
    tactics:
      - dos
    techniques:
      - T1499.004
    data_sources:
      - file_event
      - linux
  - title: Detect Kyverno Controller Panic String
    description: Detects the panic string in Kyverno controller logs indicating a type conversion error, which leads to denial of service
    platform: sigma
    severity: high
    tactics:
      - dos
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A denial-of-service vulnerability exists in the `forEach` mutation handler of Kyverno, a Kubernetes policy engine. Specifically, Kyverno versions v1.13.0 through v1.17.1 are susceptible to a flaw where an unchecked type assertion within the `ForEach` function in `pkg/engine/mutate/mutation.go` can be triggered by a specially crafted `Policy` or `ClusterPolicy`. Any user with the ability to create these policy types can exploit this vulnerability. When a `patchesJson6902` field contains a variable substitution (e.g., `{{ element.nonexistent }}`) that resolves to `nil` at runtime, the type assertion `.(string)` on a nil `interface{}` triggers an unrecoverable Go panic. This results in the background controller entering a persistent CrashLoopBackOff state, effectively halting background processing. The admission controller will also drop connections and block matching resource operations. CEL-based policies are unaffected.

## Attack Chain

1. An attacker crafts a malicious `Policy` or `ClusterPolicy` YAML manifest containing a `forEach` rule.
2. The crafted rule includes a `patchesJson6902` field with a variable substitution, such as `{{ element.nonexistent }}`, designed to resolve to `nil` at runtime.
3. The attacker applies the malicious policy to the Kubernetes cluster. This requires appropriate permissions to create `Policy` or `ClusterPolicy` resources.
4. When a resource matching the policy's `match` criteria is created or updated, the Kyverno admission controller attempts to apply the policy.
5. The `ForEach` function in `pkg/engine/mutate/mutation.go` is invoked, processing the `patchesJson6902` field.
6. The variable substitution resolves to `nil`, leading to a bare type assertion failure: `fe["patchesJson6902"].(string)`.
7. This triggers an unrecoverable Go panic, causing either the background controller (if triggered by `mutateExisting` rules) or the admission controller to terminate the connection.
8. The background controller enters a CrashLoopBackOff state due to the persistent `UpdateRequest` resources that re-trigger the panic on every restart, achieving a denial-of-service.

## Impact

Successful exploitation of this vulnerability leads to a denial of service affecting Kyverno's core functionalities within the Kubernetes cluster. An attacker can crash the background controller, halting critical background tasks such as generate rules, mutateExisting rules, and cleanup processes. The admission controller can also be affected, dropping connections and blocking resource operations that match the malicious policy's criteria. If a ClusterPolicy is used, this block extends cluster-wide. This vulnerability allows even users with limited, namespace-scoped permissions (via Policy creation) to impact the entire cluster, thus escalating privileges.

## Recommendation

*   Upgrade to Kyverno version v1.17.2 or later to patch the vulnerability (see Overview).
*   Deploy the Sigma rule `Detect Kyverno Policy with Suspicious forEach` to identify potentially malicious policies containing `forEach` loops with `patchesJson6902` fields that could trigger the vulnerability.
*   Monitor Kyverno controller logs for "panic: interface conversion: interface {} is nil, not string" errors, indicating a potential exploitation attempt (see Attack Chain, step 7).
*   Implement strict RBAC policies to limit the ability to create or modify Kyverno `Policy` and `ClusterPolicy` resources (see Impact).
