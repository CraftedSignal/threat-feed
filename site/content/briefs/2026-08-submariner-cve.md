---
title: Critical Traffic Redirection Vulnerability in Submariner
slug: 2026-08-submariner-cve
description: CVE-2026-66785 allows a malicious Kubernetes cluster to intercept inter-cluster traffic by injecting crafted network endpoints into the Submariner control plane.
date: "2026-08-20T19:18:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - kubernetes
  - networking
  - cve-2026-66785
  - traffic-interception
vendors:
  - Submariner
products:
  - Submariner
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Consequently, all network traffic intended for these arbitrary ranges from peer clusters will be rerouted through the attacker's tunnel, potentially leading to unauthorized information disclosure or network disruption.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: This vulnerability allows a malicious cluster (spoke) to redirect network traffic from other connected clusters (peer clusters) by publishing a specially crafted network endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-66785
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66785
action_plan:
  priority: immediate_escalation
  owners:
    - Infrastructure Engineering
    - Security Operations
  immediate_actions:
    - action: Upgrade Submariner deployment across all clusters
      owner: Infrastructure Engineering
      due: 24h
      evidence: CVE-2026-66785 patch requirement
  mitigation_plan:
    - priority: immediate
      action: Audit Submariner endpoint registrations
      owner: Security Operations
      addresses: CVE-2026-66785
      evidence: Endpoint validation flaw
---

CVE-2026-66785 is a critical vulnerability identified in Submariner, an open-source tool for cross-cluster networking in Kubernetes. The vulnerability resides in the way Submariner handles the registration of network endpoints across connected clusters. An attacker controlling a single 'spoke' cluster can exploit the lack of subnet validation to advertise arbitrary network ranges as being owned by their cluster. When other 'peer' clusters in the Submariner mesh receive these updates, they update their routing tables to point traffic intended for the specified subnets through the attacker-controlled tunnel. This vulnerability effectively allows for large-scale interception of inter-cluster traffic, potentially leading to unauthorized data access, information disclosure, or persistent denial-of-service conditions within the multi-cluster environment. Because this occurs at the infrastructure layer of the cluster mesh, detection and remediation require auditing of cluster registration events and endpoint advertisements within the Submariner control plane.

## Impact

Successful exploitation allows for the transparent interception of sensitive traffic traversing a multi-cluster Kubernetes environment. An attacker can use this to perform man-in-the-middle attacks on cross-cluster services, intercepting plain-text data or potentially gaining access to internal service communications. The impact is critical, as it bypasses standard network segmentation intended to isolate cluster traffic. Organizations utilizing Submariner for cross-cluster connectivity are at risk of complete network traffic compromise if any single cluster in the mesh is compromised.

## Recommendation

- Upgrade Submariner to the patched version provided by the upstream maintainers immediately to address CVE-2026-66785.
- Audit current Submariner endpoint configurations for unauthorized subnets that do not correspond to the known IP address spaces of the registered clusters.
- Implement network policy controls to limit the scope of inter-cluster communication for non-critical workloads to minimize potential blast radius if a spoke cluster is compromised.
- Review Submariner broker logs for abnormal endpoint advertisement patterns or sudden changes in cluster subnet announcements.
