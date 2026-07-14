---
title: Unauthenticated Remote Code Execution in Argo CD Repo-Server (CVE-2026-15416)
slug: 2026-07-argo-cd-rce
description: An unauthenticated remote code execution vulnerability (CVE-2026-15416) exists in Argo CD's repo-server, the GitOps engine used by Red Hat OpenShift GitOps, allowing an attacker with network access to achieve RCE and deploy malicious Kubernetes resources, leading to potential cluster compromise.
date: "2026-07-14T09:21:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - gitops
  - rce
  - cloud
  - vulnerability
  - cve
vendors:
  - Argo Project
  - Red Hat
products:
  - Argo CD
  - argo-helm < 10.0.0
  - Red Hat OpenShift GitOps
  - Red Hat OpenShift Data Foundation 4
affected_os:
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A flaw was identified in Argo CD... that could allow an unauthenticated attacker with network access to the Argo CD repo-server to achieve remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: achieve remote code execution
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1610
    technique_name: Deploy Container
    evidence: attacker may then manipulate cached data to deploy malicious Kubernetes resources to managed clusters, potentially resulting in complete cluster compromise.
    confidence_band: high
cves:
  - id: CVE-2026-15416
    cvss: 8.9
references:
  - https://access.redhat.com/security/cve/CVE-2026-15416
  - https://bugzilla.redhat.com/show_bug.cgi?id=2496732
  - https://github.com/argoproj/argo-helm/commit/0f245ab
  - https://github.com/argoproj/argo-helm/security/advisories/GHSA-47m3-95c7-g2g8
  - https://thehackernews.com/2026/07/unpatched-argo-cd-repo-server-flaw.html
  - https://www.synacktiv.com/en/publications/caught-in-the-octopus-trap-unauthenticated-rce-in-argo-cd-with-codeql
---

A critical flaw, identified as CVE-2026-15416, has been discovered in Argo CD's repo-server, the core GitOps engine utilized by Red Hat OpenShift GitOps. This vulnerability allows an unauthenticated attacker with direct network access to the repo-server to achieve remote code execution. By exploiting this flaw, attackers can manipulate cached data within the compromised repo-server. This manipulation can then be leveraged to deploy unauthorized and malicious Kubernetes resources to any managed clusters, potentially resulting in a complete compromise of the entire Kubernetes environment. The vulnerability, classified with a CVSS v3.1 score of 8.9 (High), stems from missing authentication for a critical function (CWE-306). Affected components include Argo CD instances and Red Hat OpenShift GitOps deployments, specifically `argo-helm` versions prior to 10.0.0 and certain Red Hat OpenShift GitOps and Data Foundation 4 packages.

## Attack Chain

1. An unauthenticated attacker identifies an internet-facing or internally accessible Argo CD repo-server instance.
2. The attacker establishes network connectivity to the vulnerable Argo CD repo-server.
3. The attacker exploits CVE-2026-15416, a missing authentication vulnerability, to achieve remote code execution on the repo-server process.
4. Using the RCE, the attacker manipulates the repo-server's internal cached data, potentially altering configuration or deployment instructions.
5. The compromised repo-server, under attacker control, initiates the deployment of malicious Kubernetes resources.
6. These malicious Kubernetes resources are then provisioned onto clusters managed by the Argo CD instance.
7. The deployment of malicious resources leads to a complete compromise of the targeted Kubernetes clusters, granting the attacker full control.

## Impact

Successful exploitation of CVE-2026-15416 grants an unauthenticated attacker remote code execution capabilities on the Argo CD repo-server. This level of access allows the attacker to manipulate critical GitOps infrastructure, leading to the deployment of malicious Kubernetes resources across all managed clusters. The consequences include unauthorized access to sensitive data, disruption of services, and the potential for a complete takeover of the affected Kubernetes environments. Organizations relying on Argo CD or Red Hat OpenShift GitOps are at risk of significant operational and security breaches if this vulnerability remains unpatched.

## Recommendation

* Patch CVE-2026-15416 on all affected Argo CD and Red Hat OpenShift GitOps instances immediately, specifically upgrading `argo-helm` to version 10.0.0 or later.
* Implement strict network segmentation and access controls to limit external and internal network access to Argo CD repo-servers.
* Monitor Argo CD repo-server logs for any unusual process creation, unauthorized network connections, or unexpected Kubernetes resource deployment attempts.
