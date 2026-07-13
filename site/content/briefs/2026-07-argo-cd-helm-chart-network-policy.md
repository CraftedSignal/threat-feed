---
title: Argo CD Helm Chart Vulnerability Exposes Internal APIs Leading to Cluster Compromise
slug: 2026-07-argo-cd-helm-chart-network-policy
description: A vulnerability, CVE-2026-62185, in the Argo CD Helm Chart before version 10.0.0 fails to install network policies by default, allowing any pod within a Kubernetes cluster to access critical Argo APIs, which attackers can exploit to achieve cluster compromise and remote code execution.
date: "2026-07-13T22:22:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - misconfiguration
  - network-policy
  - rce
  - supply-chain
vendors:
  - Argo Project
products:
  - Argo CD Helm Chart
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: allowing any pod on a cluster to access repo-server and other Argo APIs.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can exploit this unrestricted network access through combined attacks to achieve cluster compromise and remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: achieve cluster compromise and remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-62185
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62185
  - https://github.com/argoproj/argo-helm/security/advisories/GHSA-47m3-95c7-g2g8
  - https://www.vulncheck.com/advisories/argo-cd-helm-chart-missing-network-policy-rce
iocs:
  - type: url
    value: https://github.com/argoproj/argo-helm/security/advisories/GHSA-47m3-95c7-g2g8
  - type: url
    value: https://www.vulncheck.com/advisories/argo-cd-helm-chart-missing-network-policy-rce
ioc_counts:
  url: 2
---

CVE-2026-62185 describes a critical misconfiguration vulnerability affecting the Argo CD Helm Chart in versions prior to 10.0.0. This flaw arises because the Helm Chart, by default, does not deploy essential network policies when installing Argo CD in a Kubernetes environment. As a result, any pod within the cluster can establish unrestricted network connections to sensitive Argo CD components, including the `repo-server` and other core Argo APIs. This lack of segmentation poses a significant security risk, enabling attackers who have already compromised an arbitrary pod to perform lateral movement and privilege escalation. By chaining this vulnerability with other attack techniques, malicious actors can leverage the exposed APIs to gain full cluster compromise and execute arbitrary code remotely, severely threatening the integrity and confidentiality of the Kubernetes infrastructure and its managed applications.

## Attack Chain

1. An attacker first obtains initial access to an arbitrary pod already running within a Kubernetes cluster that uses an affected Argo CD Helm Chart installation (prior to version 10.0.0).
2. From the compromised pod, the attacker conducts internal network reconnaissance to discover the internal service endpoints for critical Argo CD components, such as the `repo-server` or `argocd-server`.
3. Due to the absence of default network policies configured by the Helm Chart (CVE-2026-62185), the attacker successfully establishes direct, unauthorized network connections from the compromised pod to the identified Argo CD APIs.
4. The attacker then interacts with the exposed Argo CD APIs to query sensitive configuration data, modify application manifests, or initiate unauthorized deployment actions within the cluster.
5. Through command injection or by introducing malicious application definitions via the accessible Argo CD APIs, the attacker injects and schedules arbitrary malicious code or container images.
6. The injected malicious code executes within the Kubernetes cluster, leading to remote code execution (RCE) on a pod, an underlying node, or potentially a control plane component.
7. The attacker leverages the RCE to achieve broader cluster compromise, which can result in data exfiltration, service disruption, or establishing persistent access mechanisms.

## Impact

A successful exploitation of CVE-2026-62185 can lead to severe and widespread impact for organizations utilizing vulnerable Argo CD Helm Chart versions. The primary consequence is the potential for complete Kubernetes cluster compromise, including remote code execution within the cluster environment. This enables attackers to gain unauthorized access to sensitive data, manipulate or destroy deployed applications, and disrupt critical services and CI/CD pipelines. The vulnerability essentially nullifies network segmentation protections, allowing a breach of even a low-privileged pod to escalate into full control over the continuous delivery system and the applications it manages, leading to significant operational disruption and data integrity loss.

## Recommendation

* Upgrade the Argo CD Helm Chart to version 10.0.0 or later immediately to deploy network policies by default, mitigating CVE-2026-62185.
* Review and implement robust network policies in your Kubernetes clusters to restrict communication between pods and critical control plane components like Argo CD APIs, as advised in the GitHub security advisory `https://github.com/argoproj/argo-helm/security/advisories/GHSA-47m3-95c7-g2g8`.
* Consult the VulnCheck advisory at `https://www.vulncheck.com/advisories/argo-cd-helm-chart-missing-network-policy-rce` for additional technical context and specific remediation guidance regarding CVE-2026-62185.
