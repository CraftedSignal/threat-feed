---
title: Argo Workflows Controller Denial-of-Service via Malformed Pod Annotation
slug: 2024-01-09-argo-workflow-dos
description: A malformed `workflows.argoproj.io/pod-gc-strategy` annotation in an Argo Workflow pod can trigger an unchecked array index in the `podGCFromPod()` function, leading to a controller-wide panic and denial-of-service.
date: "2026-04-23T21:39:21Z"
severities:
  - medium
tags:
  - argo-workflows
  - denial-of-service
  - kubernetes
vendors:
  - Argo Project
products:
  - Argo Workflows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-5jv8-h7qh-rf5p
  - https://github.com/argoproj/argo-workflows/issues/14129
  - https://github.com/argoproj/argo-workflows/issues/14263
rules:
  - title: Detect Argo Workflows Malformed Pod GC Annotation
    description: Detects the submission of Argo Workflows with a malformed workflows.argoproj.io/pod-gc-strategy annotation that can cause a denial-of-service.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect Argo Workflows Controller CrashLoopBackOff
    description: Detects when the Argo Workflows controller pod enters a CrashLoopBackOff state, potentially due to the malformed pod GC annotation vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - container
      - kubernetes
rules_count: 2
---

Argo Workflows is vulnerable to a denial-of-service attack where a malformed `workflows.argoproj.io/pod-gc-strategy` annotation within a workflow pod can crash the Argo Workflows controller. This vulnerability stems from an unchecked array index in the `podGCFromPod()` function. When the annotation value lacks a "/", the `strings.Split` function returns an array of length 1, leading to an out-of-bounds access when trying to retrieve the second element. The resulting panic occurs outside the…
