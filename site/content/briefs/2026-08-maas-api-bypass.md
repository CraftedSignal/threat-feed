---
title: Authentication Bypass in MaaS API via Header Forgery
slug: 2026-08-maas-api-bypass
description: The MaaS API incorrectly trusts X-MaaS-Username and X-MaaS-Group headers, allowing internal cluster pods to bypass authentication and escalate privileges to other tenants.
date: "2026-08-10T21:35:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - MaaS
products:
  - MaaS API
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This vulnerability allows any pod within the cluster to bypass the Kuadrant AuthPolicy gateway by forging HTTP headers
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This lack of first-party authentication enables an attacker to gain unauthorized access and escalate privileges.
    confidence_band: high
cves:
  - id: CVE-2026-14450
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14450
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - DevOps
  immediate_actions:
    - action: Review gateway header transformation policies to drop X-MaaS- headers from internal pods.
      owner: DevOps
      due: 24h
      evidence: Vulnerability allows bypass via forged X-MaaS- headers
---

A critical authentication vulnerability (CVE-2026-14450) exists in the MaaS API, where the service implicitly trusts specific HTTP headers for identity verification. By forging the 'X-MaaS-Username' and 'X-MaaS-Group' headers, any pod deployed within the same Kubernetes cluster can circumvent the Kuadrant AuthPolicy gateway. This bypass renders the platform's multi-tenancy controls ineffective, as the API accepts the provided claims without secondary validation or cryptographic proof. An attacker within the cluster environment can impersonate administrative users or other tenants, leading to unauthorized API interactions. This is particularly dangerous in multi-tenant environments where shared infrastructure relies on these specific headers to partition resources and enforce authorization.

## Impact

Successful exploitation allows for full tenant impersonation within the cluster. Concrete impact includes the unauthorized minting of Kubernetes ServiceAccount tokens in foreign namespaces, the ability to revoke legitimate API keys, and the exfiltration of sensitive model access configurations and tenant secrets. Given the CVSS score of 9.9, this vulnerability permits complete control over the affected MaaS API instances.

## Recommendation

* Immediately review ingress and gateway configurations to ensure that 'X-MaaS-Username' and 'X-MaaS-Group' headers are stripped or validated at the network perimeter before reaching the MaaS API backend.
* Implement strict mTLS and network policies to isolate pods and limit their ability to communicate directly with the MaaS API unless explicitly authorized.
* Monitor service mesh or API gateway logs for unexpected HTTP requests containing non-standard or administrative values in the 'X-MaaS' header set.
