---
title: Authorization Bypass in Label Studio Storage URI Resolution
slug: 2026-09-label-studio-auth-bypass
description: Label Studio contains an authorization bypass vulnerability in its proxy_api.py module that allows attackers to access and exfiltrate cloud storage objects belonging to other organizations.
date: "2026-09-03T15:22:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:heartex:label_studio:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authorization-bypass
  - cloud
  - data-exfiltration
vendors:
  - Heartex
products:
  - Label Studio
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: An attacker can exploit this flaw by creating a separate organization to access and exfiltrate cloud storage objects belonging to other tenants by providing arbitrary file URIs.
    confidence_band: high
cves:
  - id: CVE-2026-85211
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85211
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review access logs for proxy_api.py for abnormal URI patterns
      owner: SOC
      due: 24h
      evidence: Source describes vulnerability in proxy_api.py endpoints
  mitigation_plan:
    - priority: immediate
      action: Update Label Studio to the latest version once a patch is released by Heartex
      owner: IT Operations
      addresses: CVE-2026-85211
      evidence: NVD vulnerability entry
---

Label Studio, developed by Heartex, is vulnerable to an authorization bypass (CVE-2026-85211) within its storage management functionality. The flaw originates in the proxy_api.py module, where the application fails to properly enforce organization-level scoping when resolving storage URIs for tasks and projects. 

Defenders should note that this vulnerability allows a malicious actor to circumvent multitenancy isolation. By creating a separate organization within a shared instance, an attacker can supply arbitrary file URIs to the system. The application then inadvertently allows the attacker to presign or stream bucket contents that they are not authorized to access. This leads to unauthorized data access and potential exfiltration of sensitive cloud storage objects across tenant boundaries. The vulnerability has a CVSS v3.1 base score of 7.7, reflecting the high impact on data confidentiality in multi-tenant cloud deployments.

## Impact

Successful exploitation allows unauthorized users to access cloud storage assets belonging to other tenants. This compromises data isolation within multi-tenant Label Studio environments, potentially exposing sensitive datasets, project artifacts, or private cloud storage resources. The number of impacted organizations depends on the prevalence of multi-tenant, cloud-connected deployments of Label Studio.

## Recommendation

Prioritized actions for security teams:
- Verify your Label Studio instance configuration for multi-tenancy and restrict public or cross-organization storage URI access until a vendor-supplied patch is applied.
- Review access logs for proxy_api.py endpoints to identify anomalous requests targeting storage URIs that do not belong to the requesting user's organization.
- Monitor for unauthorized cross-tenant data access patterns in cloud storage provider logs (e.g., S3, GCS) originating from the Label Studio server identity.
