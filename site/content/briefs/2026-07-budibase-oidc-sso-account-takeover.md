---
title: Budibase OIDC SSO Account Takeover via Unverified Email Claim
slug: 2026-07-budibase-oidc-sso-account-takeover
description: A critical vulnerability in Budibase versions up to 3.38.1 allows full account takeover of any existing user, including global administrators, by exploiting a flaw in its OIDC SSO implementation that links incoming identities by email address alone without validating the `email_verified` claim, enabling an attacker to log in as a victim if they can coerce a trusted Identity Provider to assert the victim's email as unverified.
date: "2026-07-24T21:18:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - oidc
  - sso
  - account-takeover
  - budibase
  - vulnerability
vendors:
  - Budibase
products:
  - Budibase <= 3.38.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: full account takeover of any existing Budibase user, including the instance owner / global admin
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-hp6v-6jw7-gv2f
---

Budibase versions 3.38.1 and earlier are vulnerable to a critical OpenID Connect (OIDC) Single Sign-On (SSO) account takeover. The flaw stems from Budibase's logic for linking OIDC identities to existing Budibase accounts: it uses the `email` claim from the OIDC ID token as the primary identifier for account merging without verifying the `email_verified` claim. This means an attacker can manipulate a trusted Identity Provider (IdP) to issue an OIDC token containing a victim's email address with `email_verified` set to `false`. When this token is presented to Budibase, the system incorrectly merges the attacker's IdP principal with the victim's existing Budibase account, granting the attacker full access and inheriting the victim's roles, including global administrator privileges. This vulnerability is particularly potent because many IdPs, such as Keycloak and Authentik, have "Verify Email" disabled by default, or allow self-service profile editing without re-verification, making it straightforward for an attacker to craft the necessary unverified email claim.

## Attack Chain

1. An attacker gains control over a configured/trusted Identity Provider (IdP) or identifies a permissive IdP that allows asserting unverified email claims.
2. The attacker creates an account on the IdP or modifies an existing one to claim the victim's email address, ensuring the `email_verified` flag for this claim is `false`.
3. The attacker authenticates with the controlled/manipulated IdP and obtains an OIDC ID token.
4. The OIDC ID token contains the victim's email (`email = <victim@domain.com>`) and indicates that this email is `email_verified = false`.
5. The attacker initiates a standard OIDC SSO login flow to the vulnerable Budibase instance, submitting the crafted OIDC token.
6. Budibase's OIDC verification callback processes the token. It first attempts to match the IdP `sub` claim to an existing Budibase user (which fails for a fresh attacker IdP account).
7. Budibase then falls back to matching an existing user by the `email` claim. It finds the victim's account based solely on the `victim@domain.com` email without checking the `email_verified` status.
8. Budibase merges the attacker's IdP principal with the victim's existing Budibase account, issuing a session JSON Web Token (JWT) to the attacker for the victim's user ID and inheriting all the victim's roles and permissions, including global admin.

## Impact

Successful exploitation of this vulnerability leads to full account takeover of any existing Budibase user, including global administrators and the instance owner. This grants the attacker complete control over the Budibase tenant, encompassing applications, datasources, automations, user management, and access to stored datasource credentials. Organizations utilizing Budibase for their low-code applications are at risk if they have OIDC SSO configured with an IdP that can issue unverified email claims, regardless of the IdP's strictness in other areas. The immediate consequence is unauthorized access to sensitive data and critical business processes managed within Budibase.

## Recommendation

* Upgrade Budibase to a patched version immediately to resolve the vulnerability identified in Budibase <= 3.38.1.
* Configure Budibase to explicitly require `email_verified` to be `true` before using the `email` claim for account linking in OIDC SSO, as detailed in the `oidc.ts` and `sso.ts` files described in the advisory.
* Audit all SSO authentication strategies within Budibase, including OIDC, SAML, and social providers, to ensure that email-based account linking always enforces `email_verified` or similar verification mechanisms.
* If immediate patching of Budibase is not possible, enable "Verify Email" or similar email verification mechanisms on your Identity Provider (IdP) and restrict which email domains the IdP will assert.
* Where possible, prefer `sub`-based account mapping over email-based mapping in your IdP and Budibase configuration.
* Audit existing Budibase accounts for any unexpected OIDC links, especially for privileged users, and rotate affected user sessions immediately.
