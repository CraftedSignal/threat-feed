---
title: JWT Authentication Bypass in Feast
slug: 2026-09-feast-jwt-bypass
description: Feast versions 0.66.0 and earlier fail to verify JWT signatures, allowing attackers to bypass RBAC and gain unauthorized read and write access.
date: "2026-09-16T21:51:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:feast:feast:*:*:*:*:*:*:*:*
vendors:
  - Feast
products:
  - Feast (<= 0.66.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.001
    technique_name: Use Alternate Authentication Material
    evidence: Feast through 0.66.0 fails to verify JWT token signatures before establishing user identity, allowing attackers to bypass all role-based access control by presenting an unverified token with a hardcoded claim value.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92787
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Feast to version 0.66.1 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-92787 remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade Feast to 0.66.1+
      owner: IT Operations
      addresses: CVE-2026-92787
      evidence: NVD vulnerability report
---

Feast versions 0.66.0 and earlier contain a critical authentication vulnerability (CVE-2026-92787) due to a failure to verify JSON Web Token (JWT) signatures before establishing user identity. By crafting a JWT with specific, unverified claim values, an unauthenticated attacker can effectively spoof any identity, including administrative accounts. This flaw bypasses all role-based access control (RBAC) mechanisms implemented within the platform.

Successful exploitation allows an attacker to interact with the Feast server as a trusted internal entity, granting them unrestricted read and write permissions to all managed entities, feature views, data sources, and system-level permission policies. Given the nature of Feast as a feature store often central to machine learning pipelines, this vulnerability poses a significant risk to data integrity and unauthorized access to sensitive feature engineering workflows.

## Impact

Successful exploitation results in full administrative control over the Feast server. An attacker can modify feature definitions, poison training data sources, or exfiltrate sensitive feature metadata. This impacts organizations relying on Feast for ML production environments, potentially leading to unauthorized manipulation of model features and widespread data exposure across the machine learning lifecycle.

## Recommendation

- Upgrade Feast to version 0.66.1 or the latest available release immediately to address CVE-2026-92787.
- Implement strict network-level access controls to limit access to the Feast server to authorized internal subnets only.
- Review audit logs for anomalous account activity or unauthorized modifications to feature views and entities, particularly if performed by service accounts or newly created identities.
