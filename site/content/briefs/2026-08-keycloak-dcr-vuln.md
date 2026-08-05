---
title: Privilege Escalation in Keycloak Dynamic Client Registration
slug: 2026-08-keycloak-dcr-vuln
description: A vulnerability in Keycloak's Dynamic Client Registration component allows authenticated users with an Initial Access Token to forge administrative roles via improper claim validation.
date: "2026-08-05T15:21:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - identity-management
vendors:
  - Keycloak
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The default DCR policy fails to properly validate the claim path for User Property mappers, allowing them to write values to sensitive internal claim locations... an attacker... can exploit this to forge administrative roles.
    confidence_band: high
cves:
  - id: CVE-2026-16102
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16102
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Identity Management Team
  immediate_actions:
    - action: Identify and restrict access to Initial Access Tokens
      owner: Identity Management Team
      due: 24h
      evidence: Source states exploitation requires an Initial Access Token.
  mitigation_plan:
    - priority: immediate
      action: Patch Keycloak to address CVE-2026-16102
      owner: IT Operations
      addresses: CVE-2026-16102
      evidence: NVD vulnerability disclosure
---

CVE-2026-16102 affects the Dynamic Client Registration (DCR) component within Keycloak, an identity and access management solution. The vulnerability stems from an insecure default DCR policy that fails to adequately validate the claim path for User Property mappers. This oversight allows an attacker possessing a standard user account and a limited Initial Access Token to craft malicious mappers that write values to sensitive, internal claim locations. By successfully manipulating these claims, an attacker can elevate their privileges by forging administrative roles within their access token. This escalation enables the compromise of other clients, the theft of sensitive configuration secrets, and the potential for full administrative takeover of the realm. Given the core role of Keycloak in authentication, this flaw represents a significant risk for environments relying on automated client registration workflows.

## Impact

Successful exploitation results in unauthorized privilege escalation, enabling attackers to bypass access controls. Impacted organizations face the risk of account takeovers, unauthorized access to confidential secrets stored within the identity provider, and full administrative compromise of the Keycloak realm. The scope of impact is limited to organizations utilizing the Dynamic Client Registration feature.

## Recommendation

- Audit Keycloak instances to identify if Dynamic Client Registration (DCR) is enabled.
- Review and restrict access to Initial Access Tokens to highly trusted entities.
- Apply the latest security patches provided by the Keycloak project to resolve CVE-2026-16102.
- Monitor Keycloak audit logs for anomalous administrative role assignments or unusual client registration activities originating from standard user accounts.
