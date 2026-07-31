---
title: Red Hat Advanced Cluster Security Policy Bypass via Deployment Label Manipulation
slug: 2026-07-rhacs-policy-bypass
description: A vulnerability in Red Hat Advanced Cluster Security for Kubernetes (RHACS) allows an authenticated user to bypass security policy enforcement by setting the 'openshift.io/encoded-deployment-config' label to 'null'.
date: "2026-07-31T11:37:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - cloud-security
  - defense-evasion
  - cve-2026-10079
vendors:
  - Red Hat
products:
  - Advanced Cluster Security for Kubernetes
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: This bypasses deploy-time policy detection and enforcement visibility, prevents correct persistence in Central and breaks violation reporting and compliance correlation for the affected deployment.
    confidence_band: high
cves:
  - id: CVE-2026-10079
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10079
---

A vulnerability identified as CVE-2026-10079 affects Red Hat Advanced Cluster Security for Kubernetes (RHACS). The issue resides in how the platform processes Kubernetes Deployment objects. Specifically, RHACS uses the label 'openshift.io/encoded-deployment-config' to determine deployment identity metadata. 

An attacker with sufficient permissions to create Deployments in the cluster can explicitly set this label to "null". This action forces the RHACS Central component to misinterpret the workload's identity, effectively assigning it an empty UID, name, and labels while defaulting the namespace to "default". This misidentification causes a complete bypass of deploy-time policy detection and enforcement mechanisms. Furthermore, it results in a lack of visibility into the workload, prevents correct persistence within the security database, and breaks compliance correlation and violation reporting for the affected deployment. This vulnerability is critical for organizations relying on RHACS for automated security governance in multi-tenant or managed Kubernetes environments, as it allows for the deployment of non-compliant or malicious workloads without triggering platform-based alerting or blocking controls.

## Impact

The impact of this vulnerability is significant as it undermines the core security enforcement capabilities of the RHACS platform. By evading policy checks, attackers can deploy workloads that violate corporate security standards or contain malicious configurations without detection. This results in reduced visibility for security teams, broken compliance reporting, and the potential for persistent, unauthorized access within the container environment. The severity is reflected in the CVSS v3.1 base score of 8.5.

## Recommendation

1. Audit current Kubernetes Deployment manifests for the presence of the 'openshift.io/encoded-deployment-config' label set to "null" or other obfuscated values.
2. Implement Kubernetes Admission Controllers to prevent users from injecting arbitrary metadata labels, specifically targeting the 'openshift.io/' prefix.
3. Review audit logs for unexpected Deployment creation events in non-standard namespaces, particularly those where metadata appears inconsistent with organizational naming conventions.
4. Ensure that RHACS Central is updated to the latest version as provided by Red Hat to remediate the metadata processing logic associated with CVE-2026-10079.
