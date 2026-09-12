---
title: Prowler SAML Domain Claiming Enables Cross-Tenant Account Takeover
slug: 2026-09-prowler-saml-takeover
description: Prowler versions through 5.30.0 contain an improper authentication vulnerability where the SAML ACS finish flow incorrectly derives the target tenant from an asserted email domain, enabling cross-tenant account takeover.
date: "2026-09-12T00:57:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - saml
  - account-takeover
  - cloud-security
  - prowler
vendors:
  - Prowler
products:
  - Prowler (<= 5.30.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: An attacker can initiate the flow without requiring any action from the victim by leveraging IdP-initiated SSO.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550.001
    technique_name: Application Access Token
    evidence: The vulnerable ACS finish flow could create membership and issue a SAMLToken using a tenant derived from the asserted email domain.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-h8m9-jgf8-vwvp
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Prowler to the latest secure version.
      owner: IT Operations
      due: 24h
      evidence: Source provides recommendation to bind token issuance to validated configuration.
  mitigation_plan:
    - priority: immediate
      action: Review configured SAML domains in Prowler for unauthorized entries.
      owner: SOC
      addresses: Account Takeover
      evidence: SAML domain claiming is the primary vector for tenant spoofing.
---

Prowler versions through 5.30.0 contain an improper authentication vulnerability (CWE-287) in the SAML authentication flow. The application incorrectly trusts the email domain asserted within a SAMLResponse to identify the target tenant for token issuance, rather than binding the token to the tenant associated with the validated SAML configuration. An attacker who has configured their own SAML identity provider (IdP) for their own tenant can forge SAML assertions to claim accounts in other tenants. Because the application uses a hardcoded auto-connect feature and allows IdP-initiated SSO, an attacker can bypass user interaction and trigger the vulnerable flow to obtain a JWT for a victim user. If successful, this grants the attacker full access to the victim's cloud security audit findings and enables lateral movement into other tenants through the token switch endpoint.

## Attack Chain

1. The attacker configures a legitimate SAML identity provider for their own tenant on the target Prowler instance.
2. The attacker triggers an IdP-initiated SSO flow against the target Prowler instance.
3. The attacker presents a signed SAMLResponse to the ACS endpoint, specifying a `NameID` (email) belonging to a victim user in a different tenant (e.g., `user@victim.com`).
4. The Prowler SAML ACS finish logic parses the `user.email` from the assertion.
5. The application code splits the email string to extract the domain, using it to look up the tenant in the database, ignoring the actual SAML configuration validated for the route.
6. The `sociallogin.connect()` method executes, linking the victim's existing account to the attacker's forged assertion.
7. The system issues a temporary SAML token bound to the resolved (but incorrect) tenant.
8. The attacker exchanges the SAML token for a JWT and utilizes the `tokens/switch` endpoint to gain full access to the victim's actual tenant.

## Impact

This vulnerability allows for unauthorized cross-tenant account takeover. Successful exploitation grants an attacker full read/write access to all cloud security audit findings (AWS, GCP, Azure) within the victim's tenant. Additionally, attackers can enumerate, modify, or delete compliance findings, manipulate integration secrets, and leverage the token switch endpoint to pivot into any other tenants where the victim user maintains membership.

## Recommendation

1. Upgrade all Prowler instances to a patched version immediately once available from the maintainer.
2. Perform a manual review of all configured SAML configurations in the Prowler admin interface to identify unauthorized or suspicious domain mappings.
3. Audit system logs for unexpected or anomalous SAML authentication successes, specifically looking for `ACS` requests originating from unknown IdP entity IDs.
4. Implement network-level restrictions on access to Prowler API endpoints if the instance is exposed to the public internet, limiting access to known corporate IP ranges until patching is complete.
5. Review the `ProwlerSocialAccountAdapter.pre_social_login` logic in the codebase to ensure tenant binding is locked to the validated SAML configuration rather than the user email domain.
