---
title: Argo Workflows Controller Denial-of-Service via Malformed Pod Annotation
slug: 2024-01-09-argo-workflow-dos
description: A malformed `workflows.argoproj.io/pod-gc-strategy` annotation in an Argo Workflow pod can trigger an unchecked array index in the `podGCFromPod()` function, leading to a controller-wide panic and denial-of-service.
date: "2026-04-23T21:39:21Z"
type: advisory
types:
  - advisory
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

Argo Workflows is vulnerable to a denial-of-service attack where a malformed `workflows.argoproj.io/pod-gc-strategy` annotation within a workflow pod can crash the Argo Workflows controller. This vulnerability stems from an unchecked array index in the `podGCFromPod()` function. When the annotation value lacks a "/", the `strings.Split` function returns an array of length 1, leading to an out-of-bounds access when trying to retrieve the second element. The resulting panic occurs outside the controller's recovery scope, causing the entire controller process to terminate. The affected versions include 3.6.5 through 3.6.19, 3.7.0-rc1 through 3.7.12, and 4.0.0-rc1 through 4.0.3. This vulnerability was introduced in commit [#14129](https://github.com/argoproj/argo-workflows/issues/14129).

## Attack Chain

1. An attacker crafts a malicious Argo Workflow YAML file.
2. The YAML includes a `podMetadata` section defining annotations for the workflow pod.
3. Within the annotations, the `workflows.argoproj.io/pod-gc-strategy` key is set to a value that does not contain a forward slash ("/"), such as "NoSlash".
4. The attacker submits the crafted workflow to the Argo Workflows controller using `kubectl apply -n argo -f malicious-workflow.yaml`.
5. The Argo Workflows controller receives the workflow definition and creates a corresponding pod based on the specification.
6. The `podGCFromPod()` function in `/workflow/controller/pod/controller.go` attempts to parse the `workflows.argoproj.io/pod-gc-strategy` annotation.
7. The `strings.Split` function splits the annotation value, resulting in an array with only one element.
8. The code attempts to access `parts[1]`, causing a panic due to an out-of-bounds array access and crashes the controller, resulting in a denial-of-service.

## Impact

Successful exploitation of this vulnerability allows any user with the ability to submit workflows to crash the Argo Workflows controller. The controller will enter a crash loop, rendering the entire Argo Workflows deployment unavailable. Since the controller is responsible for managing and executing workflows, all workflow processing is halted, leading to a denial-of-service condition. This can severely impact organizations relying on Argo Workflows for their CI/CD pipelines or other automated tasks. The attacker requires only `create` permission on Workflow resources to execute this attack.

## Recommendation

*   Upgrade to a patched version of Argo Workflows (v3.6.4 or earlier, v3.6.20+, v3.7.13+, or v4.0.4+) to remediate the vulnerability as described in [GHSA-5jv8-h7qh-rf5p](https://github.com/advisories/GHSA-5jv8-h7qh-rf5p).
*   Implement input validation on workflow submissions to reject workflows with malformed `workflows.argoproj.io/pod-gc-strategy` annotations. See the PoC workflow example provided in [GHSA-5jv8-h7qh-rf5p](https://github.com/advisories/GHSA-5jv8-h7qh-rf5p) for examples of vulnerable annotation values.
*   Deploy the Sigma rule `Detect Argo Workflows Malformed Pod GC Annotation` to detect workflow submissions containing potentially malicious annotations.
