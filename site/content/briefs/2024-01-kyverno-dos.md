---
title: Kyverno Controller Denial of Service via forEach Mutation Panic
slug: 2024-01-kyverno-dos
description: An unchecked type assertion in Kyverno versions v1.13.0 to v1.17.1 allows a user with permission to create a Policy or ClusterPolicy to crash the cluster-wide background controller into a persistent CrashLoopBackOff, leading to a denial of service, by crafting a malicious policy that triggers a nil pointer dereference in the forEach mutation handler.
date: "2024-01-27T12:00:00Z"
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

A denial-of-service vulnerability exists in the `forEach` mutation handler of Kyverno, a Kubernetes policy engine. Specifically, Kyverno versions v1.13.0 through v1.17.1 are susceptible to a flaw where an unchecked type assertion within the `ForEach` function in `pkg/engine/mutate/mutation.go` can be triggered by a specially crafted `Policy` or `ClusterPolicy`. Any user with the ability to create these policy types can exploit this vulnerability. When a `patchesJson6902` field contains a…
