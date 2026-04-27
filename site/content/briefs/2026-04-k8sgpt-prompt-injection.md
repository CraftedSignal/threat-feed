---
title: k8sGPT Operator Vulnerable to Prompt Injection
slug: 2026-04-k8sgpt-prompt-injection
description: k8sGPT versions before 0.4.32 are vulnerable to prompt injection due to deserialization of AI-generated YAML without proper validation in the auto-remediation pipeline, potentially leading to arbitrary code execution within the Kubernetes cluster.
date: "2026-04-24T16:41:39Z"
severities:
  - high
tags:
  - prompt-injection
  - kubernetes
  - ai
  - vulnerability
vendors:
  - k8sgpt-ai
products:
  - k8sgpt
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
references:
  - https://github.com/advisories/GHSA-rp7v-4384-hfrp
rules:
  - title: Detect Privileged Container Creation via k8sGPT
    description: Detects the creation of privileged containers, a common technique for escalating privileges within a Kubernetes cluster.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - auditd
      - linux
  - title: Detect Host Path Mounts in Kubernetes Deployments via k8sGPT
    description: Detects the mounting of host paths, a technique for gaining access to the host filesystem from within a container.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - auditd
      - linux
rules_count: 2
---

k8sGPT is an open-source project that leverages AI to analyze and remediate Kubernetes cluster issues. A critical vulnerability exists in k8sGPT versions prior to 0.4.32, specifically within the k8sGPT-Operator component. The vulnerability stems from the auto-remediation pipeline in `object_to_execution.go`, which deserializes AI-generated YAML directly into a Kubernetes Deployment object without adequate validation. This lack of validation allows for prompt injection, where malicious YAML…
