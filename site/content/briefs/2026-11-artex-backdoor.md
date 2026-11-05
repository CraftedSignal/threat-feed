---
brief_id: brief-2026-11-05-artex-backdoor
event_id: brief-2026-11-05-artex-backdoor
revision: 1
activity_at: "2026-11-05T10:04:43Z"
title: 'ARTEX Penetration Testing Tool: Backdoored Docker Images'
slug: 2026-11-artex-backdoor
description: Attackers are distributing backdoored Docker images of the ARTEX offensive security tool that grant unauthenticated root access via a hidden command injection vulnerability in the login handler.
date: "2026-11-05T10:04:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
tags:
  - supply-chain
  - backdoor
  - container
  - credential-access
  - artex
  - linux
products:
  - ARTEX (Backdoored Docker builds)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: The rest runs through sh -c as root and the output is returned, before any credential check.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: That's an unauthenticated root shell on every install, and it never shows up in a code review.
    confidence_band: high
references:
  - https://thehackernews.com/2026/11/backdoored-docker-image-for-artex-ai.html
rules:
  - title: Detect ARTEX Backdoor Command Injection Attempt
    description: Detects unauthenticated root shell access attempts via the backdoored ARTEX login handler by monitoring for shell execution patterns originating from the application process.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit container registry and running containers for the listed malicious Docker namespaces.
      owner: IT Operations
      due: 24h
      evidence: Source identifies 62 consoles globally serving the backdoored build.
  hunt_leads:
    - lead: Search container logs for unauthenticated shell execution patterns originating from ARTEX login containers.
      technique_id: T1059.004
      data_needed:
        - Container stdout/stderr logs
        - Docker event logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The backdoor runs through sh -c as root on every unauthenticated request.
---

CERT-In reported that backdoored versions of the ARTEX penetration testing console, distributed via Docker Hub, are being used to grant attackers unauthenticated root shell access. The malicious routine injects a hidden `verifyCaptcha()` function into the login handler, which executes input via `sh -c` as root if a specific secret marker is detected in the CAPTCHA field. As of November 4, 2026, 62 instances of these backdoored consoles have been identified globally.

## Attack Chain

1. Attacker pushes a modified, backdoored image of the ARTEX console to Docker Hub namespaces.
2. Target user pulls and deploys the malicious Docker image, typically as a root-privileged container.
3. Attacker accesses the internet-facing ARTEX login portal.
4. Attacker provides the secret marker within the CAPTCHA field to the login handler.
5. The hidden `verifyCaptcha()` function executes arbitrary commands as root via `sh -c`.
6. Attacker gains persistence and full system control, using the host to pivot into production environments and steal credentials.

## Impact

The vulnerability results in an unauthenticated root shell on every installation of the backdoored ARTEX instance. Once compromised, the instance provides attackers with access to stored findings, live credentials, captured sessions, and local network positioning, facilitating lateral movement into production systems and the potential theft of financial or digital assets.

## Recommendation

* Identify and audit all running containers in your environment to ensure that no ARTEX instances are present.
* Restrict outbound network access for any security-testing or administrative consoles to prevent unauthorized communication.
* Enforce a strict policy against pulling or running container images from unverified or untrusted Docker Hub namespaces.
* Immediately decommission and purge any Docker containers identified as using the backdoored `tomicdd/artex` or `congdonglinux/artex` images.
