---
brief_id: brief-2026-11-16-container-image-build
event_id: brief-2026-11-16-container-image-build
revision: 1
activity_at: "2026-11-16T10:21:26Z"
title: Defense Evasion via In-Container Image Building
slug: 2026-11-container-image-build
description: The detection of container image build utilities (e.g., docker, buildah, nerdctl) executing within a running container indicates a potential attempt to bypass security admission controls and registry scanning.
date: "2026-11-16T10:21:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic sourced from verified Elastic detection rules repository.
tags:
  - defense-evasion
  - containers
  - kubernetes
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1612
    technique_name: Build Image on Host
    evidence: Adversaries build a container image directly inside a running container or pod to bypass defenses that inspect images pulled from a registry.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/defense_evasion_container_image_build_inside_a_container.toml
  - https://attack.mitre.org/techniques/T1612/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule for in-container build utilities targeting docker, buildah, and nerdctl.
      owner: Detection Engineering
      due: 48h
      evidence: Elastic detection rule daa0d56b-9149-475c-8bf7-bce8a337eed8
  hunt_leads:
    - lead: Identify execution of docker, buildah, or nerdctl within container workloads outside of dedicated CI/CD namespaces.
      technique_id: T1612
      data_needed:
        - Container process execution logs (e.g., Elastic Defend, Sysmon for Linux)
        - Orchestrator namespace metadata
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Building an image on the host (or inside a pod) bypasses defenses that monitor for the retrieval of malicious images.
---

## Overview

Adversaries may build container images directly within a running container or pod to evade standard security controls. By assembling an image locally from a Dockerfile and executing it, attackers bypass defenses that typically inspect images pulled from a central registry. While legitimate in dedicated CI/CD pipelines (e.g., Tekton, Argo, Jenkins, Kaniko), this behavior is anomalous in standard production workloads and often signals manual, hands-on-keyboard post-exploitation activity.

## Impact

Successful execution of this technique allows an adversary to assemble and run custom malicious tooling without triggering registry-based image scanning or admission control policies, potentially facilitating the deployment of privileged or host-namespaced pods.

## Recommendation

Detection engineers should monitor for the execution of build utilities within containers. For organizations using Elastic, deploy the "Container Image Built Inside a Container" rule and baseline sanctioned build namespaces to reduce false positives.

## Response and Remediation

- Investigate the target container and namespace to determine if it is a sanctioned CI/CD workload.
- Analyze the command line for the build context, Dockerfile path, and image tag.
- Inspect the parent process to identify whether the build was invoked manually or via an automated process.
- Isolate suspicious containers and remove unauthorized images to maintain environment integrity.
