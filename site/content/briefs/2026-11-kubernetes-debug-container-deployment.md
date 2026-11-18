---
brief_id: brief-2026-11-18-kubernetes-debug-container-deployment
event_id: brief-2026-11-18-kubernetes-debug-container-deployment
revision: 1
activity_at: "2026-11-18T22:27:37Z"
title: Kubernetes Pod Creation Using Common Debug or Base Images
slug: 2026-11-kubernetes-debug-container-deployment
description: This rule identifies first-seen Kubernetes pod creation requests using common debug, base, or container-runtime images that are frequently used by attackers to stage interactive containers or bypass image controls.
date: "2026-11-18T22:27:37Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
affected_os:
  - kubernetes
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
    evidence: Base and debug images are frequently used by attackers to deploy short-lived or interactive "throwaway" containers for reconnaissance, payload staging, or command execution.
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1610
    technique_name: Deploy Container
    evidence: This rule identifies successful, first-seen pod deployments that use commonly abused troubleshooting, base, container-runtime, or image-building images.
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1612
    technique_name: Build Image on Host
    evidence: Container runtime and build images are used to run nested containers or build images on-host, bypassing registry-based image controls.
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/execution_common_debug_or_base_image_pod_creation.toml
rules:
  - title: Kubernetes Pod Creation Using Common Debug or Base Images
    description: Detects successful Kubernetes pod creation requests using commonly abused base, debug, and build images that are seen for the first time within a five-day window by a specific user or source.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1609
      - T1610
      - T1612
    data_sources:
      - kubernetes
      - kubernetes
rules_count: 1
---

## Overview

Attackers frequently deploy short-lived or interactive "throwaway" containers to facilitate reconnaissance, payload staging, or command execution within Kubernetes clusters. This detection identifies successful pod creation requests using commonly abused base images (e.g., Alpine, BusyBox, Ubuntu, Debian), debugging utilities (e.g., Netshoot, network-multitool), or container runtime/build tools (e.g., Docker-in-Docker, Podman, BuildKit, Buildah, Kaniko) that have not been observed in the previous five days. Container runtime and build images are specifically used to run nested containers or build images on-host, effectively bypassing registry-based image controls.

## Attack Chain

- **Execution**: The attacker uses `kubectl` or API requests to deploy pods using specialized images for command execution (T1609) or general container deployment (T1610).
- **Defense Evasion**: The use of container-runtime or build-tool images on-host allows for building images and running workloads that bypass standard registry controls (T1612).

## Impact

Unauthorized deployment of these containers enables cluster reconnaissance, lateral movement, payload staging, and hidden on-host image construction, potentially leading to the compromise of cluster security policies.

## Recommendation

- Investigate the workload owner, namespace, and authentication method to verify if the pod creation is associated with an authorized troubleshooting or build workflow.
- Review pod specifications for privileged mode, hostPath mounts, and access to sensitive secrets.
- Correlate with concurrent audit activity such as secret access, discovery, exec/attach sessions, or rapid pod deletion.
- If unauthorized, isolate the pod using network policies, revoke exposed credentials, and remove the artifact.
