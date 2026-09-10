---
title: SPIFFE/SPIRE Identity Spoofing via Node-Level Compromise
slug: 2026-09-spiffe-spire-identity-misuse
description: An attacker with root access on a Kubernetes node can manipulate cgroup metadata to deceive the SPIRE agent, allowing for the unauthorized harvesting of SVIDs belonging to co-located workloads.
date: "2026-09-10T12:49:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - identity
  - kubernetes
  - spiffe
  - spire
  - spoofing
  - cloud-security
vendors:
  - SPIFFE
  - SPIRE
products:
  - SPIRE Agent
  - SPIRE Server
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: We show how the trust assumption at the core of every machine-identity system collapses once an attacker obtains root on that node.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Our research demonstrates post-exploitation techniques that could allow an attacker with root access on a compromised Kubernetes node to misuse an open standard.
    confidence_band: high
references:
  - https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Infrastructure Security
  immediate_actions:
    - action: Perform an audit of SPIRE registration selectors for sensitive workloads to ensure reliance on strong, non-spoofable attributes.
      owner: Infrastructure Security
      due: 72h
      evidence: Minimize reliance on weak selectors
  hunt_leads:
    - lead: Detect processes attempting to access the SPIRE Workload API UNIX socket from unauthorized or anomalous namespaces.
      technique_id: T1068
      data_needed:
        - Socket connection logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: SPIRE agent accepts requests from workloads locally over the Workload API
---

This research identifies a critical risk in SPIFFE/SPIRE deployments where the security of machine identity is fundamentally tied to the integrity of the underlying host. When an attacker gains root access to a Kubernetes node, they can manipulate the Linux control group (cgroup) metadata that the SPIRE agent relies upon for workload attestation. By spoofing these attributes, an attacker can trick the SPIRE agent into identifying a malicious process as a legitimate, co-located workload.

Once successfully impersonated, the attacker's process can request and receive SVIDs (X.509 or JWT) that are authorized for the target workload. This allows the attacker to assume the identity of the target within the trust domain, enabling unauthorized access to services, databases, or APIs that rely on workload-to-workload mTLS or token-based authentication. While the researchers released the 'Spooffe' tool to demonstrate this vector, there is currently no evidence of this technique being used in the wild. Defenders must treat root access to a node as a total loss of identity assurance for all workloads residing on that host.

## Attack Chain

1. Attacker gains initial access to a Kubernetes node and escalates privileges to root.
2. Attacker inspects the SPIRE agent configuration to understand the required cgroup-based selectors for co-located workloads.
3. Attacker identifies a target workload's identity and its associated cgroup parameters on the compromised node.
4. Attacker creates a new process or container on the compromised node, configured with cgroup metadata matching the target workload's attributes.
5. Attacker executes the SPIRE Workload API client within the spoofed process environment.
6. The SPIRE agent collects the forged cgroup selectors from the attacker's process.
7. The SPIRE agent attests the process as the target workload and requests an SVID from the SPIRE server based on the matched registration entry.
8. The SPIRE server issues the legitimate SVID to the attacker, granting them the target workload's identity for subsequent abuse.

## Impact

Successful exploitation allows for the complete impersonation of any workload co-located on a compromised node. This can result in unauthorized data exfiltration, lateral movement within a service mesh, and the bypass of identity-based authorization controls. Because these identities are cryptographically signed, the impersonation is highly credible to other services within the trust domain.

## Recommendation

* Prioritize hardening of all Kubernetes nodes and restrict root access to reduce the likelihood of the initial node compromise.
* Minimize the attack surface by prohibiting privileged containers and restricting host access for sensitive workloads.
* Evaluate SPIRE registration policies to minimize reliance on weak or easily spoofed selectors.
* Use 'Spooffe' (as provided in the Unit 42 research) to audit existing workload selector configurations and assess potential impact if a node were compromised.
* Implement runtime security monitoring to detect unauthorized container escapes or unexpected process execution within critical namespaces.
