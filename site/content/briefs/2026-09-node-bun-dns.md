---
title: Uncommon DNS Requests via Node.js or Bun Runtimes
slug: 2026-09-node-bun-dns
description: Adversaries leverage compromised dependencies in Node.js or Bun development workflows to perform anomalous DNS lookups for command-and-control, staging, or exfiltration activities.
date: "2026-09-18T19:05:46Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - supply-chain
  - command-and-control
  - nodejs
  - bun
  - javascript
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Adversaries may leverage these tools via a supply chain attack of a compromised developer's package to execute malicious code and steal/exfiltrate data.
    confidence_band: high
rules:
  - title: Detect Uncommon DNS Requests via Node.js or Bun
    description: Detects DNS lookups initiated by Node.js or Bun processes, which may indicate supply chain compromise and C2 beaconing.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - dns_query
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma detection rule to identify anomalous runtime DNS activity.
      owner: Detection Engineering
      due: 48h
      evidence: Rule targets the described TTP of runtime-initiated DNS requests.
  hunt_leads:
    - lead: Search for DNS lookups originating from node or bun processes in CI/CD logs.
      technique_id: T1071.004
      data_needed:
        - DNS lookup logs mapped to process names.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source notes that compromised dependencies use runtimes to contact C2 infrastructure.
  mitigation_plan:
    - priority: short_term
      action: Enforce dependency pinning and restrict build system network access.
      owner: IT Operations
      addresses: Supply chain poisoning TTPs
      evidence: Source recommends enforcing dependency pinning and adding detections for these lookups.
---

Adversaries are increasingly exploiting software supply chain vulnerabilities to embed malicious code within developer dependencies. When these compromised packages are installed or executed, they leverage JavaScript runtimes such as Node.js or Bun to perform network operations, including DNS lookups to attacker-controlled infrastructure. This activity often occurs during legitimate developer tasks, CI/CD pipeline execution, or build processes, allowing the malicious traffic to blend in with normal build-time network noise. By using the runtime to initiate these requests, attackers can establish command-and-control channels, resolve subdomains for payload delivery, or exfiltrate environment variables and credentials (such as repository tokens or API keys). Defenders must differentiate between legitimate dependency resolution and anomalous DNS activity to detect supply chain compromises early in the infection cycle.

## Attack Chain

1. A threat actor injects malicious code into a widely used package via a compromised developer account or direct contribution to an open-source project.
2. The target developer or build system executes a package manager command, triggering the download and installation of the poisoned dependency.
3. Lifecycle scripts (e.g., preinstall, postinstall) within the malicious package execute automatically under the context of Node.js or Bun.
4. The malicious script initiates a DNS request via the runtime to resolve a high-entropy or newly registered subdomain.
5. The runtime receives the resolved IP address, establishing a command-and-control connection to the attacker's infrastructure.
6. The script exfiltrates sensitive data such as .npmrc contents, cloud credentials, or SSH keys to the remote host.
7. The attacker pulls second-stage payloads or executes additional commands on the compromised host to maintain persistence.

## Impact

Successful exploitation allows attackers to gain unauthorized access to CI/CD pipelines, developer workstations, and production environments. This can lead to the compromise of proprietary source code, the theft of sensitive API tokens and credentials, and the potential injection of further malicious code into downstream software products. The scale of impact is limited by the reach of the compromised dependency and the access level of the user or system executing the build.

## Recommendation

Prioritize monitoring of JavaScript runtime network behavior in CI/CD and developer environments.
* Enable process-level DNS logging to capture the Image and associated DNS Query for Node.js and Bun.
* Establish a baseline for normal dependency resolution domains to reduce false positives from internal service discovery.
* Revoke credentials (SSH keys, cloud secrets, repository tokens) immediately if a system exhibits anomalous DNS requests associated with runtime execution.
* Implement dependency pinning and verify lockfiles to prevent the introduction of unvetted or malicious package updates.
* Block egress traffic for build systems that do not require broad internet access, restricting them to approved package registries only.
