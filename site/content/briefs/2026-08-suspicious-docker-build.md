---
title: Suspicious Docker Build Execution in Temporary Directories
slug: 2026-08-suspicious-docker-build
description: Detection of docker build commands executed on Dockerfiles located in temporary directories, a common indicator of unauthorized container deployment or persistence attempts on Linux hosts.
date: "2026-08-07T15:16:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - container-security
  - persistence
vendors:
  - Docker
products:
  - Docker Engine
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1610
    technique_name: 'Execution: Container Administration Command'
    evidence: The following analytic detects docker build being executed on Dockerfiles within the /tmp directory.
    confidence_band: high
rules:
  - title: Detect Suspicious Docker Build in Temporary Directories
    description: Detects docker build being executed on Dockerfiles within /tmp, which is an atypical location for legitimate builds.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1610
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for detecting docker build activity in /tmp.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic provided by Splunk Security Content.
  hunt_leads:
    - lead: Search for historical 'docker build' commands containing /tmp paths.
      technique_id: T1610
      data_needed:
        - Endpoint process logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Presence of this behavior is often indicative of post-exploitation.
---

Security researchers have identified a pattern of suspicious activity involving the use of the 'docker build' command on Linux systems. Attackers often stage malicious Dockerfiles within temporary directories such as /tmp to minimize their footprint or obfuscate their activity. Because the /tmp directory is typically used for transient files and is rarely a legitimate location for software builds, this behavior is a high-fidelity indicator of potential unauthorized container deployment or post-exploitation activities. This detection is particularly relevant for Linux environments using the Docker Engine, where attackers may seek to gain additional persistence or facilitate further command execution by leveraging the container runtime. Defenders should monitor for command-line arguments that reference the /tmp path during docker build operations to identify potential malicious intent early in the kill chain.

## Attack Chain

1. Attacker gains initial access to the Linux host via an exploit or stolen credentials.
2. Attacker downloads or creates a malicious Dockerfile.
3. Attacker places the Dockerfile into a writable temporary directory like /tmp.
4. Attacker executes 'docker build' pointing to the temporary directory using the -f flag or by executing from within that path.
5. The Docker daemon processes the malicious configuration, often pulling malicious base images or executing internal commands during the build phase.
6. The container image is successfully built and registered in the local Docker engine.
7. Attacker triggers the new container to execute malicious code, achieving persistence or gaining a sandbox environment for further operations.

## Impact

Successful exploitation allows an attacker to establish persistent containerized backdoors, bypass host-level security controls, or gain a stable execution environment for secondary tools. This activity is frequently observed in Linux Post-Exploitation scenarios where the attacker attempts to expand their influence within the compromised infrastructure.

## Recommendation

* Deploy the provided Sigma rule to detect suspicious 'docker build' executions originating from temporary directories.
* Establish a process for reviewing developer-approved usage of build environments to reduce noise from legitimate development activities.
* Enable Sysmon for Linux (or equivalent EDR telemetry) to capture full command-line arguments and parent process information, which is critical for identifying the origin of the build command.
