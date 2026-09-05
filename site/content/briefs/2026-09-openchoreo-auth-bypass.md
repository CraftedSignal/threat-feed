---
title: OpenChoreo Cluster-Gateway Authentication Bypass and RCE
slug: 2026-09-openchoreo-auth-bypass
description: The OpenChoreo cluster-gateway fails to authenticate callers to internal management APIs, allowing unauthorized actors to perform arbitrary Kubernetes API mutations and access Secrets across connected data planes.
date: "2026-09-05T00:07:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:openchoreo:openchoreo:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - kubernetes
  - cloud
vendors:
  - OpenChoreo
products:
  - cluster-gateway (< 1.0.3, 1.1.0-1.1.2, 1.2.0-rc.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The internal listener authenticates no caller and its request validator permits mutating HTTP methods.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attacker executes commands in pods via /api/exec/.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1505.004
    technique_name: 'Server Software Component: IIS Modules'
    evidence: The cluster-gateway provides no compensating authorization, bypassing data-plane access controls.
    confidence_band: high
cves:
  - id: CVE-2026-73842
    cvss: 9
    epss: 0.0018
references:
  - https://github.com/advisories/GHSA-rh53-xvx2-j327
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade OpenChoreo to 1.0.3, 1.1.3, or 1.2.0
      owner: IT Operations
      due: 24h
      evidence: Fixed in 1.0.3, 1.1.3, and 1.2.0.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to cluster-gateway management ports
      owner: IT Operations
      addresses: CVE-2026-73842
      evidence: Direct exploitability depends on the network isolation of the internal listener.
---

The OpenChoreo cluster-gateway component suffers from a critical authentication bypass vulnerability (CVE-2026-73842) affecting its internal management APIs, specifically /api/proxy/, /api/exec/, and /api/wirelogs/. These endpoints are designed to tunnel requests to connected Kubernetes data planes but lack any caller authentication or authorization checks. Furthermore, despite being intended for read-only telemetry, the validator allows arbitrary HTTP methods, including those that mutate state or disclose sensitive information. An attacker with network reach to the internal listener can interact with the downstream Kubernetes APIs of any connected data plane as if they were the cluster-gateway itself. This vulnerability creates a significant risk of Secret exfiltration, arbitrary workload modification, and remote code execution via pod exec functionality.

## Attack Chain

1. Attacker gains network reach to the OpenChoreo cluster-gateway internal management port.
2. Attacker probes the internal API endpoints: /api/proxy/, /api/exec/, or /api/wirelogs/.
3. Attacker crafts a malicious request to /api/proxy/ to reach the Kubernetes API server of a connected data plane.
4. Attacker bypasses the non-existent authentication mechanism, as the gateway blindly forwards the request.
5. Attacker sends a POST or PUT request to create or modify Kubernetes resources (e.g., Deployments or Services) in a target namespace.
6. Attacker sends a request to /api/exec/ to execute arbitrary commands inside a target pod, achieving RCE.
7. Attacker reads Kubernetes Secrets in tenant namespaces to harvest database credentials or cloud service keys.

## Impact

The vulnerability grants unauthorized full control over connected Kubernetes data planes. Successful exploitation leads to the disclosure of sensitive credentials stored in Kubernetes Secrets, the deployment of malicious workloads, and remote command execution within the tenant environment. This affects all versions of OpenChoreo prior to the specified fixed releases (1.0.3, 1.1.3, 1.2.0), effectively neutralizing data-plane level security controls.

## Recommendation

1. Upgrade OpenChoreo immediately to version 1.0.3, 1.1.3, or 1.2.0 to resolve CVE-2026-73842.
2. Implement strict network segmentation to restrict access to the cluster-gateway internal listener.
3. Ensure that internal management ports are not reachable from untrusted workload namespaces using Kubernetes NetworkPolicies.
4. Audit logs for anomalous HTTP POST or PUT requests to /api/proxy/ that target the Kubernetes API server.
