---
title: Information Disclosure via Workload Secret Logging in Edgelesssys Contrast
slug: 2026-09-edgelesssys-contrast-leak
description: Edgelesssys Contrast versions 1.9.0 through 1.12.1 insecurely log workload secrets to stdout, allowing unauthorized access to sensitive credentials by users with pod log permissions.
date: "2026-09-27T03:03:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:edgelesssys:contrast:*:*:*:*:*:*:*:*
tags:
  - credential-access
  - kubernetes
  - information-disclosure
vendors:
  - Edgelesssys
products:
  - Contrast (>= 1.9.0, < 1.12.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The initializer logs the full NewMeshCert response — which contains the workload secret — to standard output.
    confidence_band: high
cves:
  - id: CVE-2025-71423
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71423
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Contrast runtime to 1.12.2 or later.
      owner: IT Operations
      due: 48h
      evidence: Source designates 1.12.2 as the fixed version.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict Kubernetes RBAC roles allowing access to pod logs.
      owner: Security Engineering
      addresses: CVE-2025-71423
      evidence: Exploitation requires access to pod logs via get or list permissions.
---

Edgelesssys Contrast, a confidential-computing runtime for Kubernetes, contains an information disclosure vulnerability in versions 1.9.0 prior to 1.12.2. The initializer component performs insecure logging of the full NewMeshCert response at the INFO level to standard output. This output contains critical workload secrets used for encrypted storage and Vault integration. 

Any Kubernetes user or service account with 'get' or 'list' permissions on pod logs can extract these secrets directly from the container logs. Because these secrets protect encrypted storage and integration channels, their exposure constitutes a full compromise of the affected workload's security boundaries. This vulnerability is a regression of a previously addressed flaw (GHSA-h5f8-crrq-4pw8). Defenders must verify their Contrast deployment versions and restrict access to Kubernetes pod logs as an immediate mitigation.

## Impact

The vulnerability allows for the unauthorized retrieval of workload secrets, leading to a complete compromise of confidential computing environments. Attackers can leverage these exposed secrets to decrypt stored data or impersonate workloads in integrated systems like HashiCorp Vault. This flaw exposes sensitive organizational data across all Kubernetes clusters running affected versions of Contrast.

## Recommendation

* Upgrade Edgelesssys Contrast to version 1.12.2 or later to eliminate the insecure logging behavior.
* Audit Kubernetes Role-Based Access Control (RBAC) to identify and limit users and service accounts with broad 'get' or 'list' access to pod logs.
* Rotate any secrets that have been accessible via pod logs in clusters where versions 1.9.0 through 1.12.1 were deployed.
* Monitor Kubernetes audit logs for suspicious 'get' or 'list' requests targeting pod logs, specifically looking for users attempting to access logs of the Contrast initializer component.
