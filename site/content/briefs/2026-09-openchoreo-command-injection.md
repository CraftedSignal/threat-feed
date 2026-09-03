---
title: Authenticated OS Command Injection in OpenChoreo Workflow Plane
slug: 2026-09-openchoreo-command-injection
description: Authenticated users can trigger OS command injection in OpenChoreo workflow templates by supplying crafted parameters that are insecurely interpolated into shell execution scripts.
date: "2026-09-03T00:03:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openchoreo:openchoreo:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - kubernetes
  - podman
vendors:
  - OpenChoreo
products:
  - openchoreo (< 1.0.4, >= 1.1.0, < 1.1.4, >= 1.2.0-rc.1, < 1.2.0-rc.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Some developer-controlled workflow parameters were interpolated directly into shell program text executed through sh -c.
    confidence_band: high
cves:
  - id: CVE-2026-73667
    cvss: 8.8
    epss: 0.00615
references:
  - https://github.com/advisories/GHSA-2mw5-23gm-pccq
  - https://github.com/openchoreo/openchoreo/tree/release-v1.x/samples/getting-started/workflow-templates
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade OpenChoreo to versions 1.0.4, 1.1.4, or 1.2.0-rc.2
      owner: IT Operations
      due: 24h
      evidence: Source Patches section
  mitigation_plan:
    - priority: immediate
      action: 'Set hostUsers: false for all privileged containers'
      owner: IT Operations
      addresses: Container isolation
      evidence: Source Patches section
---

OpenChoreo Workflow Plane is affected by an OS command injection vulnerability (CVE-2026-73667) stemming from the insecure interpolation of developer-controlled workflow parameters into shell commands executed via 'sh -c'. An authenticated user with sufficient permissions to configure or trigger workflows can supply crafted parameter values containing shell metacharacters, allowing them to alter the intended command execution and run arbitrary commands within the workflow pod. 

The vulnerability is particularly critical because certain build and publish templates run Podman containers in a privileged mode without Kubernetes pod user-namespace isolation enabled. In these configurations, an attacker successfully performing command injection gains UID 0 within a privileged container. Because the container lacks user namespace isolation, this UID 0 is mapped directly to UID 0 on the host, granting the attacker significant capabilities and potentially facilitating a container escape or node-level compromise. The issue was addressed by moving away from direct shell interpolation to the use of container environment variables and argument vectors.

## Attack Chain

1. Attacker gains authentication access to the OpenChoreo environment with permissions to configure or trigger workflow templates.
2. Attacker identifies a workflow template that accepts user-supplied parameters interpolated into a shell script executed by the workflow engine.
3. Attacker submits a workflow request containing malicious shell metacharacters (e.g., ; , &&, |) within a vulnerable input parameter.
4. The OpenChoreo Workflow Plane processes the template and directly interpolates the malicious parameter into a shell command string.
5. The workflow pod executes the resulting malicious string via 'sh -c', triggering the attacker-supplied commands within the pod context.
6. The injected commands execute with the privileges assigned to the container (e.g., root/UID 0).
7. If the container is running in privileged mode without user namespace isolation (hostUsers: false), the attacker attempts to interact with host-level resources or devices to escalate privileges or escape the container.
8. Final objectives may include credential exfiltration (Git/registry/service account tokens), source code theft, or persistent access to the Kubernetes node.

## Impact

Successful exploitation allows an authenticated attacker to gain unauthorized code execution within the context of a workflow pod. Depending on the environment and template configuration, this leads to the potential exposure of sensitive data, including Git and registry credentials, Kubernetes service account tokens, and source code. Because privileged containers without user namespace isolation map the container's root user to the host's root user, the impact can extend to a full compromise of the underlying Kubernetes node if the attacker manages to exploit kernel or node-level vulnerabilities from within the privileged container context.

## Recommendation

1. Upgrade OpenChoreo immediately to version 1.0.4, 1.1.4, or 1.2.0-rc.2.
2. For clusters running custom workflow templates, manually review and update templates to remove direct shell interpolation, replacing them with quoted shell variables passed through container environment variables or separate argument-vector entries.
3. Ensure that all containers utilizing privileged Podman execution have `hostUsers: false` explicitly set in their security context to enable user namespace isolation and prevent root-to-root mapping on the host.
4. Enforce strict RBAC policies to restrict the ability to create, modify, or trigger workflows to a highly limited set of trusted users.
5. Audit existing workflow templates for any instances of shell metacharacter usage in user-defined parameters to identify potential historical exploitation attempts.
