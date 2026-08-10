---
title: 'CVE-2026-18949: Privilege Escalation via Overly Permissive Service Account in Open Data Hub'
slug: 2026-08-odh-dashboard-privilege-escalation
description: A vulnerability in the Open Data Hub odh-dashboard allows an attacker with a compromised Service Account token to escalate to cluster-administrator privileges due to excessive RBAC permissions.
date: "2026-08-10T21:39:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - cloud-native
  - kubernetes
vendors:
  - Red Hat
products:
  - odh-dashboard
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This vulnerability allows an attacker, who has compromised the dashboard's Service Account (SA) token, to exploit overly broad permissions granted to the SA.
    confidence_band: high
cves:
  - id: CVE-2026-18949
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18949
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Audit and restrict RBAC permissions for the odh-dashboard Service Account
      owner: IT Operations
      addresses: CVE-2026-18949
---

A security flaw (CVE-2026-18949) has been identified in the odh-dashboard component of the Open Data Hub platform. The vulnerability stems from an overly permissive Role-Based Access Control (RBAC) configuration assigned to the dashboard's Service Account (SA). An attacker who has already gained access to the dashboard's SA token can leverage these excessive permissions to perform unauthorized actions within the Kubernetes cluster. By escalating privileges to cluster-administrator level, the attacker can access sensitive information, including cluster credentials, secret keys, and API tokens, while effectively bypassing multi-tenant isolation boundaries. This vulnerability is significant for organizations running machine learning or data science workloads on Open Data Hub, as it allows lateral movement and total cluster control following an initial compromise of the dashboard service.

## Impact

The vulnerability poses a severe risk to cluster integrity and multi-tenant isolation. Successful exploitation leads to full cluster-administrator access, enabling an attacker to exfiltrate sensitive data, manipulate cluster workloads, and compromise other tenants hosted within the same infrastructure. Organizations using Open Data Hub are advised to review RBAC assignments immediately.

## Recommendation

* Audit the ClusterRole and RoleBinding objects associated with the odh-dashboard Service Account to ensure the principle of least privilege is applied.
* Implement strict monitoring for Service Account token usage patterns, focusing on API requests that deviate from standard dashboard operational baseline.
* Evaluate the use of projected service account tokens with shorter lifespans and audience restrictions to limit the impact of a potential token compromise.
