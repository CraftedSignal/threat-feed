---
title: Privilege Escalation in crun via libkrun and passt Networking
slug: 2026-09-crun-priv-esc
description: A privilege escalation vulnerability in crun versions 1.29 and later allows attackers to execute container-image payloads with host root privileges when using libkrun with passt networking.
date: "2026-09-10T11:06:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:crun_project:crun:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - container-security
  - linux
products:
  - crun (>= 1.29)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A flaw was found in crun... crun can execute attacker-controlled payload from the container image with host root privileges.
    confidence_band: high
cves:
  - id: CVE-2026-84042
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84042
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Audit container environments for crun version 1.29 or greater
      owner: Security Engineering
      due: 48h
      evidence: The issue is a regression in crun 1.29. It affects crun >= 1.29
  mitigation_plan:
    - priority: immediate
      action: Disable libkrun or passt networking for rootful containers until a patch is available
      owner: IT Operations
      addresses: CVE-2026-84042
      evidence: When crun is built with libkrun and a container is started rootful with passt networking... crun can execute attacker-controlled payload
---

A security vulnerability identified as CVE-2026-84042 affects the crun container runtime when compiled with libkrun support. The issue arises when a container is executed with root privileges and configured to use passt networking via the 'krun.use_passt' setting. Under these specific conditions, a regression introduced in version 1.29 allows an attacker to manipulate the container execution environment. Specifically, the runtime may inadvertently execute malicious payloads defined within the container image with the effective privileges of the host root user. This represents a critical breakdown in container isolation, as an attacker with control over the container image or runtime configuration can achieve full system compromise. The vulnerability affects all versions of crun starting from 1.29. Defenders should audit container runtime configurations to identify systems utilizing libkrun and passt networking simultaneously.

## Attack Chain

1. Attacker crafts a malicious container image containing a payload designed to execute upon container startup.
2. Attacker gains access to a host system where the container runtime is configured to use crun >= 1.29.
3. Attacker ensures the container runtime is built with libkrun and configured with passt networking (krun.use_passt).
4. Attacker triggers the deployment of the malicious container image using rootful execution.
5. The crun runtime initializes the container using libkrun and passt networking.
6. Due to the vulnerability, the runtime executes the payload within the image context.
7. The payload executes with host root privileges, bypassing intended container isolation.
8. Attacker gains full control over the host system.

## Impact

Successful exploitation allows a low-privileged actor to escalate privileges to root on the host machine. This affects any infrastructure relying on crun as its container runtime, specifically those utilizing libkrun-based sandboxing. Impact includes full system compromise, exfiltration of sensitive host-level data, and potential persistence mechanisms being established within the host environment.

## Recommendation

1. Upgrade crun to a version where this regression is patched once available from your distribution vendor.
2. Until a patch is applied, disable the use of libkrun or passt networking (krun.use_passt) for rootful containers.
3. Audit container orchestration configurations (e.g., Kubernetes, Podman, or Docker) to identify environments running crun 1.29 or later.
4. Implement restricted container security policies to prevent the deployment of untrusted container images.
