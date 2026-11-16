---
brief_id: brief-2026-11-16-kubernetes-privileged-pod
event_id: brief-2026-11-16-kubernetes-privileged-pod
revision: 1
activity_at: "2026-11-16T10:21:50Z"
title: Kubernetes Privileged Pod Created
slug: 2026-11-kubernetes-privileged-pod
description: This rule identifies the creation of Kubernetes pods with privileged containers enabled, which bypasses container isolation and provides access to host resources, facilitating potential container escapes and subsequent malicious activity.
date: "2026-11-16T10:21:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - 'Data Source: Kubernetes'
  - 'Domain: Kubernetes'
  - 'Use Case: Threat Detection'
  - 'Tactic: Execution'
  - 'Tactic: Privilege Escalation'
  - 'Resources: Investigation Guide'
  - 'Noise: Medium'
  - 'Performance: Fast'
  - 'Profile: Recommended'
  - 'Threat: Container Escape'
  - 'Rule Type: Custom Query (KQL)'
  - 'Platform: Kubernetes'
  - 'Domain: Containers'
  - 'Domain: Cloud'
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: A highly privileged container has access to the node's resources and breaks the isolation between containers. If compromised, an attacker can use the privileged container to gain access to the underlying host.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1610
    technique_name: Deploy Container
    evidence: This rule detects when a user creates a pod/container running in privileged mode.
    confidence_band: high
references:
  - https://media.defense.gov/2021/Aug/03/2002820425/-1/-1/1/CTR_KUBERNETES%20HARDENING%20GUIDANCE.PDF
  - https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_privileged_pod_created.toml
rules:
  - title: Kubernetes Privileged Pod Created
    description: This rule detects when a user creates a pod or container running in privileged mode, which breaks container isolation and gives access to host resources.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege-escalation
    techniques:
      - T1610
      - T1611
    data_sources:
      - kubernetes
      - kubernetes
rules_count: 1
---

## Overview
Kubernetes clusters allow the creation of privileged pods, which grant containers access to the host's resources and break the isolation between containers. This configuration allows the container nearly all the same access as processes running on the host, which can be exploited by an adversary to gain access to the underlying host.

## Attack Chain
- Execution: Adversaries may use the deployment of a privileged container to run code with host-level access.
- Privilege Escalation: Access to the host provides the adversary with the opportunity to achieve follow-on objectives, such as establishing persistence, moving laterally within the environment, or setting up a command and control channel.

## Impact
Compromised nodes may allow an adversary to achieve follow-on objectives, including establishing persistence, moving laterally, or establishing command and control channels from the host.

## Recommendation
- Audit Kubernetes logs for pod creation where the security context explicitly sets `privileged: true` and the request authorization decision is 'allow'.
- Maintain an exclusion list for verified, legitimate container images that require privileged access.
- Investigate the specific user or service account responsible for the creation and determine the business necessity of the pod.
- Isolate suspected nodes using cordon and drain procedures to stop new pods from being scheduled and safely evict existing pods, terminate the privileged pod, and perform a full audit for indicators of host-level compromise.
