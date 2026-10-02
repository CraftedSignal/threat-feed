---
title: Authentication Bypass in Dogtag PKI CMCAuthForEST Plugin
slug: 2026-10-dogtag-pki-auth-bypass
description: An authentication bypass vulnerability in the Dogtag PKI CMCAuthForEST plugin allows authenticated users to obtain CA-signed certificates with arbitrary subject names due to improper session attribute handling during EST fullcmc requests.
date: "2026-10-02T22:27:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:dogtag_pki:pki_core:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - pki
  - privilege-escalation
vendors:
  - Dogtag PKI
products:
  - pki-core
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The SSL_CLIENT_CERT session attribute retains the EST subsystem's agent certificate, which causes downstream authorization checks to treat the request as agent-privileged.
    confidence_band: high
cves:
  - id: CVE-2026-104988
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104988
action_plan:
  priority: elevated
  owners:
    - SOC
    - PKI Administrators
  immediate_actions:
    - action: Review CA issuance logs for suspicious or unauthorized certificate subject names.
      owner: PKI Administrators
      due: 48h
      evidence: CVE-2026-104988 allows obtaining CA-signed certificates with arbitrary subject names.
  mitigation_plan:
    - priority: immediate
      action: Patch pki-core to the vendor-recommended version correcting CMCAuthForEST logic.
      owner: IT Operations
      addresses: CVE-2026-104988
      evidence: NVD advisory CVE-2026-104988.
---

A security vulnerability (CVE-2026-104988) exists within the CMCAuthForEST authentication plugin of Dogtag PKI (pki-core). The issue arises when an Enrollment over Secure Transport (EST) fullcmc enrollment request is submitted using Basic Authentication in the absence of an end-user TLS client certificate. In this scenario, the application fails to correctly clear the session state. Specifically, the 'SSL_CLIENT_CERT' session attribute persists and retains the EST subsystem's agent certificate. Because downstream authorization mechanisms rely on this attribute to verify the requester's identity, the system incorrectly evaluates the request as having been made by an agent with elevated privileges. An authenticated user can leverage this logic flaw to successfully request and obtain CA-signed certificates containing arbitrary subject names, effectively bypassing standard enrollment restrictions. This vulnerability poses a significant risk to the integrity of the PKI environment, as unauthorized entities could issue valid certificates.

## Impact

The vulnerability allows an authenticated user to perform unauthorized certificate issuance. If exploited, an attacker could obtain valid CA-signed certificates with arbitrary subject names, facilitating impersonation, unauthorized authentication to internal services, and potential bypass of security controls that rely on certificate-based identity. The impact is assessed as high given the ability to manipulate the primary trust mechanism of the organization.

## Recommendation

* Monitor for unauthorized certificate requests targeting the EST interface, specifically those lacking a client TLS certificate but succeeding via Basic Auth.
* Audit CA logs for certificates issued with unexpected or non-standard subject names.
* Apply the security patch for Dogtag PKI (pki-core) provided by the vendor to ensure proper clearing of the SSL_CLIENT_CERT session attribute when authentication methods are mismatched.
* Review all service accounts associated with EST subsystems to ensure that only authorized administrative entities have access to fullcmc enrollment endpoints.
