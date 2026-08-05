---
title: 'CVE-2026-16443: Signature Validation Bypass in Keycloak SAML Metadata Import'
slug: 2026-08-keycloak-saml-bypass
description: An authentication bypass vulnerability in Red Hat Build of Keycloak allows unauthenticated attackers to forge SAML assertions by manipulating metadata import settings to disable signature validation.
date: "2026-08-05T15:20:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - saml
  - identity-management
vendors:
  - Red Hat
products:
  - Red Hat Build of Keycloak
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker to forge a SAML response and gain unauthorized access to a user account by knowing their external identifier.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: This issue allows an unauthenticated attacker to forge a SAML response and gain unauthorized access to a user account.
    confidence_band: high
cves:
  - id: CVE-2026-16443
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16443
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Red Hat Build of Keycloak to versions addressing CVE-2026-16443
      owner: IT Operations
      due: 48h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Manually verify SAML signature validation settings in all IdP configurations
      owner: IT Operations
      addresses: CVE-2026-16443
      evidence: Vulnerability description regarding metadata import logic
---

CVE-2026-16443 describes a critical security flaw in the SAML metadata import functionality within the keycloak-services component of Red Hat Build of Keycloak. The vulnerability arises when an administrator or automated process imports identity provider metadata that lacks specific usage attributes for keys. Under these conditions, the Keycloak engine incorrectly disables signature validation for subsequent SAML responses, even if a valid signing certificate is present in the metadata. This oversight creates an authentication bypass scenario, as the application fails to verify the integrity and origin of incoming SAML tokens. An unauthenticated attacker, knowing a target user's external identifier, can forge a SAML response, masquerade as a legitimate user, and gain unauthorized access to the affected environment. The flaw poses a significant risk to organizations relying on Keycloak for identity brokering and single sign-on services, as it fundamentally compromises the trust relationship between the service provider and the identity provider.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to user accounts within applications protected by Keycloak. In enterprise environments, this may lead to full account takeover, unauthorized access to sensitive corporate resources, and potential data exfiltration. The vulnerability impacts all deployments of Red Hat Build of Keycloak utilizing SAML identity brokering features that rely on metadata imports.

## Recommendation

Prioritized actions for detection and remediation:

- Update Red Hat Build of Keycloak to the latest patched version provided by Red Hat to resolve CVE-2026-16443.
- Audit all configured SAML identity providers in the Keycloak admin console to ensure "Signature Validation" is explicitly enabled and not reliant on default or metadata-derived settings.
- Review SAML authentication logs for suspicious successful login events where the assertion signature could not be verified or where assertions originated from unexpected identity provider endpoints.
