---
title: Capsule Namespace and Service Metadata Enforcement Bypass
slug: 2026-09-capsule-bypass
description: A vulnerability in Capsule's metadata validation logic allows tenant owners to bypass configured forbidden labels and annotations, enabling unauthorized configuration changes to Kubernetes resources.
date: "2026-09-18T19:51:33Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Individual Tenant
tags:
  - kubernetes
  - misconfiguration
  - privilege-escalation
  - validation-bypass
vendors:
  - Project Capsule
products:
  - Capsule (<= 0.13.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated tenant owner can exploit this flaw to apply forbidden metadata to their namespaces or services, potentially bypassing isolation boundaries.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-gjw4-3v3v-rqxg
action_plan:
  priority: elevated
  owners:
    - Security Operations
    - Infrastructure Engineering
  immediate_actions:
    - action: Audit Capsule forbidden label and annotation lists for mixed-case entries
      owner: Infrastructure Engineering
      due: 48h
      evidence: The bug is deterministic and requires the denied list to mix at least one capitalised key with lowercase keys.
  mitigation_plan:
    - priority: immediate
      action: Normalize forbidden list entries to lowercase to prevent the sorting mismatch defect
      owner: Infrastructure Engineering
      addresses: Capsule (<= 0.13.5)
      evidence: A list that is uniformly lowercase sorts identically under both orders and is not affected.
---

Capsule, a multi-tenancy operator for Kubernetes, provides isolation controls through `forbiddenLabels` and `forbiddenAnnotations` configurations. These controls prevent tenant owners from applying specific metadata to namespaces, services, or nodes that could disrupt cluster-wide policies, such as Pod Security Admission or network routing. The enforcement mechanism relies on the `ExactMatch` function in `pkg/api/forbidden_list.go` to determine if a submitted key is prohibited.

The vulnerability stems from a logical flaw in how `ExactMatch` processes the forbidden list. The code sorts the list case-insensitively and then performs a binary search using byte-order comparison. Because binary searches require the slice to be sorted in the same order as the comparison method, this mismatch causes the search to fail for certain keys. When the administrator's forbidden list contains mixed-case entries (e.g., camelCase alongside lowercase), the binary search can incorrectly report that a prohibited key is absent. This failure is silent and allows the tenant owner to successfully apply forbidden metadata, effectively bypassing critical isolation controls.

## Attack Chain

1. Attacker (tenant owner) identifies that they possess standard tenant-level access to create or patch namespaces or services within their assigned Capsule tenant.
2. Attacker inspects the environment to confirm the presence of a non-empty, mixed-case forbidden label or annotation policy (e.g., both `kubernetes.io/metadata.name` and camelCase vendor labels exist in the denied list).
3. Attacker crafts a Kubernetes resource request (e.g., `kubectl label`) targeting their own namespace or service, including a key that is explicitly present in the admin's forbidden list but affected by the binary search sorting mismatch.
4. The Capsule validating webhook intercepts the API request and triggers the `ValidateForbidden` function.
5. The `ExactMatch` primitive performs an incorrect binary search on the forbidden list due to the case-insensitive/byte-order sort conflict.
6. The `ExactMatch` function returns a false "not forbidden" result, causing `ValidateForbidden` to allow the submission.
7. The Kubernetes API server persists the resource with the forbidden metadata, bypassing intended isolation boundaries.
8. Attacker leverages the newly applied metadata to influence cluster behavior, such as altering security contexts, network policy enforcement, or scheduling decisions.

## Impact

The vulnerability enables tenant owners to bypass isolation and security controls intended to be enforced by the cluster administrator. The successful application of forbidden metadata can result in security configuration overrides, such as disabling Pod Security Admission enforcement, circumventing namespace isolation, or manipulating service network exposure via LoadBalancer annotations. While the impact is gated by the presence of specific configuration patterns, the bypass provides a mechanism for privilege escalation within the multi-tenant environment.

## Recommendation

1. Audit current Capsule configurations to identify if mixed-case forbidden lists (labels or annotations) are in use, as these represent the primary vector for this bypass.
2. Implement an immediate review of Capsule-managed tenant resources for unauthorized metadata keys, specifically looking for keys intended to be forbidden by admin policy.
3. Update Capsule to the patched version that reconciles the sorting order and binary search logic (awaiting vendor patch/version announcement).
4. Until a patch is applied, ensure forbidden lists contain only lowercase keys if possible, as uniformly lowercase lists are not impacted by this sorting defect.
