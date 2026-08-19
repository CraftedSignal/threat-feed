---
title: Excessive RBAC Permissions in Submariner-Operator
slug: 2026-08-submariner-rbac-flaw
description: A critical RBAC vulnerability in the submariner-operator component allows a compromised Kubernetes cluster to overwrite endpoint configurations, enabling inter-cluster traffic interception.
date: "2026-08-18T18:55:26Z"
lastmod: "2026-08-19T20:38:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - kubernetes
  - cloud
  - privilege-escalation
  - rbac
  - rhacm
  - cve
vendors:
  - Red Hat
products:
  - Red Hat Advanced Cluster Management for Kubernetes 2
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The submariner-k8s-broker-cluster Role, which is assigned to joined clusters, possesses excessive permissions. This allows a compromised cluster to alter network configurations.
    confidence_band: high
cves:
  - id: CVE-2026-66780
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66780
  - https://access.redhat.com/security/cve/CVE-2026-66780
  - https://bugzilla.redhat.com/show_bug.cgi?id=2507524
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70496
  - https://access.redhat.com/security/cve/CVE-2026-70496
  - https://bugzilla.redhat.com/show_bug.cgi?id=2511032
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Apply security patches for CVE-2026-66780 to all managed clusters
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-66780 disclosure
  mitigation_plan:
    - priority: immediate
      action: Review Kubernetes API audit logs for unusual Endpoint resource modifications
      owner: SOC
      addresses: CVE-2026-66780
      evidence: Red Hat security advisory
updates:
  - at: "2026-08-19T20:38:32Z"
    level: L2
    summary: added coverage for Red Hat Advanced Cluster Management for Kubernetes 2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70496
---

A critical vulnerability (CVE-2026-66780) exists within the submariner-operator component of Red Hat Advanced Cluster Management for Kubernetes 2. The issue stems from the `submariner-k8s-broker-cluster` Role, which is automatically assigned to joined clusters in a cluster mesh architecture. This role contains excessive permissions that violate the principle of least privilege. Specifically, an attacker who gains control over a single member cluster within the mesh can leverage these elevated permissions to modify shared network configuration objects. By overwriting endpoint information for other clusters in the broker, the attacker can redirect inter-cluster traffic through their compromised node. This facilitates large-scale Man-in-the-Middle (MITM) attacks against internal services communicating across the mesh. Given the potential for complete traffic interception within a multi-cluster Kubernetes environment, this vulnerability poses a severe risk to data confidentiality and integrity.

## Attack Chain

1. Attacker gains initial access to a single Kubernetes cluster member participating in the Submariner mesh.
2. Attacker leverages local cluster privileges to impersonate the service account associated with the `submariner-k8s-broker-cluster` Role.
3. Attacker authenticates against the central Kubernetes API server managing the broker.
4. Attacker issues a `PUT` or `PATCH` request to the broker's API endpoints to modify `Endpoint` or `Cluster` custom resources.
5. Attacker injects malicious endpoint metadata, pointing other clusters' tunnel traffic to the attacker-controlled cluster IP.
6. Submariner controllers on other clusters automatically update their routing tables based on the malicious broker data.
7. Inter-cluster traffic is routed through the attacker-controlled node, enabling decryption or modification of the data stream.

## Impact

Successful exploitation allows for full interception, modification, or denial-of-service of inter-cluster network traffic across the entire mesh. This affects all Red Hat Advanced Cluster Management for Kubernetes 2 deployments utilizing the Submariner add-on, potentially impacting any sector relying on multi-cluster Kubernetes orchestration for production workloads.

## Recommendation

Prioritize the immediate audit of all Submariner service account permissions in your cluster broker. 
1. Patch the submariner-operator component to the latest vendor-provided version that restricts the `submariner-k8s-broker-cluster` role.
2. Implement Kubernetes API audit logging to monitor for anomalous modifications to `Endpoint` objects by service accounts.
3. Review all RBAC policies for cross-cluster communication channels to ensure they follow the principle of least privilege.
4. Use network policies to restrict cluster-to-cluster traffic to only explicitly required services, reducing the blast radius of a potential MITM scenario.
