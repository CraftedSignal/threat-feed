---
title: Information Disclosure in Red Hat Advanced Cluster Management via HelmRelease Manipulation
slug: 2026-08-rhacm-secret-leak
description: An authenticated user with HelmRelease creation permissions can exploit CVE-2026-73137 to exfiltrate sensitive credentials from arbitrary Kubernetes namespaces in Red Hat Advanced Cluster Management.
date: "2026-08-20T21:19:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - exfiltration
  - vulnerability
  - cloud
  - kubernetes
vendors:
  - Red Hat
products:
  - Advanced Cluster Management
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This allows the GetSecret() function in the HelmRelease controller to fetch sensitive credentials from any namespace, which are then sent to an attacker-controlled Helm repository.
    confidence_band: high
cves:
  - id: CVE-2026-73137
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73137
---

CVE-2026-73137 represents a security vulnerability within the multicloud-operators-subscription component of Red Hat Advanced Cluster Management (RHACM). The vulnerability arises from improper validation of the `secretRef.Namespace` field within HelmRelease objects. An attacker who possesses the necessary privileges to create or modify HelmRelease objects can manipulate this field to force the controller's `GetSecret()` function to access and retrieve sensitive data - such as image pull secrets, service account tokens, or API keys - from namespaces they would not otherwise be permitted to access. Once retrieved, these secrets are subsequently transmitted to an attacker-controlled Helm repository. This flaw essentially allows for cross-namespace credential exfiltration within the cluster, leading to significant information disclosure and potential privilege escalation by leveraging the stolen credentials to access additional resources or services.

## Attack Chain

1. Attacker gains authenticated access to a Kubernetes cluster with sufficient permissions to create or update `HelmRelease` custom resources.
2. Attacker crafts a malicious `HelmRelease` resource object targeting the RHACM controller.
3. Attacker modifies the `secretRef.Namespace` field within the `HelmRelease` manifest to point to a target namespace containing sensitive secrets.
4. Attacker updates the `spec.chart.repository` field to point to an attacker-controlled Helm repository.
5. The RHACM `multicloud-operators-subscription` controller processes the malicious `HelmRelease` object.
6. The `GetSecret()` function executes, erroneously fetching secrets from the unauthorized namespace due to the manipulated reference.
7. The controller transmits the stolen sensitive secret data to the attacker-controlled repository endpoint.
8. Attacker retrieves the exfiltrated credentials from their repository logs or monitoring services.

## Impact

Successful exploitation allows for unauthorized information disclosure of sensitive secrets across the Kubernetes cluster. This can facilitate lateral movement or privilege escalation within the affected multicloud environment by granting the attacker access to administrative tokens or encrypted credentials intended for internal use only.

## Recommendation

* Monitor for suspicious `HelmRelease` object creations or updates in the Kubernetes API audit logs, specifically looking for abnormal values in `secretRef.Namespace` fields.
* Audit current RBAC policies for users with `HelmRelease` creation permissions to ensure the principle of least privilege is applied, specifically restricting users from managing charts in sensitive or cross-project namespaces.
* Update RHACM to the latest patched version once released by Red Hat to resolve the underlying logic error in the `multicloud-operators-subscription` controller.
