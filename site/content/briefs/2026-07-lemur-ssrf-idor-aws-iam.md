---
title: Lemur 1.9.0 Server-Side Request Forgery and IDOR Lead to AWS IAM Compromise
slug: 2026-07-lemur-ssrf-idor-aws-iam
description: A low-privilege user with a freshly-provisioned SSO account in Netflix's Lemur certificate management service (versions <= 1.9.0) can exploit a Server-Side Request Forgery (SSRF) vulnerability in the ACME authority creation endpoint to reach the AWS EC2 Instance Metadata Service (IMDS), exfiltrating AWS STS credentials, and leveraging a creator-equality Insecure Direct Object Reference (IDOR) vulnerability for permanent access to PKI private keys, resulting in AWS IAM compromise and persistent certificate access.
date: "2026-07-03T10:43:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - idor
  - aws
  - iam
  - pki
  - credential-access
  - exfiltration
  - webserver
vendors:
  - Netflix
  - Amazon
products:
  - github.com/Netflix/lemur <= 1.9.0
  - AWS IAM
  - AWS STS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Lemur auto-creates every new SSO identity as `active=True` with no admin approval; any SSO holder Lemur's IdP accepts becomes an active Lemur user.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1538
    technique_name: Steal Application Access Token
    evidence: the ACME authority-creation endpoint accepts an attacker-supplied `acme_url` and fetches it server-side with no allowlist, reaching EC2 IMDS at `169.254.169.254`... hands the attacker AWS STS credentials of the lemur worker role.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: AWS, that means `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` returns the worker's `AccessKeyId`, `SecretAccessKey`, and STS `Token` to the attacker.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: the certificate key-fetch endpoint grants `cert.user` (the original creator) unconditional access even after ownership is transferred to a different team. ... walks away with a permanent copy of any TLS private key Lemur issued.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Transfer ownership to victim admin... `owner` is now `victim-admin@netflix.example`. `creator_id` is unchanged at `1` (the attacker). This is the audit-trail laundering step.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-v2wp-frmc-5q3v
  - https://asciinema.org/a/CFYaoR2fxWEIdZDf
iocs:
  - type: ip
    value: 169.254.169.254
  - type: url
    value: http://169.254.169.254/latest/meta-data/iam/security-credentials/lemur-acme-role
  - type: email
    value: attacker@evil.example
  - type: email
    value: victim-admin@netflix.example
  - type: url
    value: https://asciinema.org/a/CFYaoR2fxWEIdZDf
ioc_counts:
  email: 2
  ip: 1
  url: 2
rules:
  - title: Detect Lemur ACME SSRF to IMDS
    description: Detects attempts to create an ACME authority in Lemur with an acme_url pointing to the AWS EC2 Instance Metadata Service (IMDS) IP address, indicating an SSRF attempt to exfiltrate AWS STS credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - exfiltration
    techniques:
      - T1538
      - T1567
    data_sources:
      - webserver
  - title: Detect Lemur Certificate Private Key Exfiltration After Ownership Transfer
    description: Detects an Insecure Direct Object Reference (IDOR) attempt where an original certificate creator attempts to fetch a private key after the certificate's ownership has been transferred, indicating persistent unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1552.004
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability chain impacting Netflix's Lemur certificate management service, specifically version 1.9.0 and earlier releases, allows any SSO-authenticated user to achieve AWS IAM compromise and permanent PKI key access. The attack leverages three distinct weaknesses: automatic provisioning of new SSO identities as `active=True` without admin approval (affecting `lemur/lemur/auth/views.py:300-308`), an unauthenticated Server-Side Request Forgery (SSRF) in the ACME authority creation endpoint allowing `acme_url` to target the EC2 IMDS (`lemur/lemur/plugins/lemur_acme/acme_handlers.py:161-201`), and a creator-equality Insecure Direct Object Reference (IDOR) that grants the original certificate creator unconditional access to its private key, even after ownership transfer (`lemur/lemur/certificates/views.py:734`). This combination enables an attacker to exfiltrate AWS STS credentials of the Lemur worker role and maintain permanent access to any TLS private key they originally issued, circumventing standard remediation efforts.

## Attack Chain

1.  **SSO Auto-Provisioning (Initial Access)**: An attacker authenticates via corporate SSO, which Lemur automatically provisions as an active user (`active=True`, `auto_provisioned=true`) without administrative approval or role restrictions.
2.  **ACME Authority Creation with SSRF (Credential Access)**: The attacker, now an authenticated Lemur user, creates a new ACME authority, providing a malicious `acme_url` pointing to `http://169.254.169.254/latest/meta-data/iam/security-credentials/lemur-acme-role`.
3.  **IMDS Credential Exfiltration (Exfiltration)**: The Lemur worker process makes a server-side request to the IMDS endpoint as specified in `acme_url`, retrieves AWS STS credentials (AccessKeyId, SecretAccessKey, Token), and returns them in the API response to the attacker via the `ssrf_response_body` field.
4.  **Issue Certificate**: The attacker uses their newly acquired STS credentials (or their existing Lemur session) to issue a new certificate via Lemur, ensuring they are the original `creator_id` of the certificate.
5.  **Ownership Transfer (Defense Evasion)**: To obfuscate their activity, the attacker transfers ownership of the newly issued certificate to a legitimate victim administrator's email (`owner:"victim-admin@netflix.example"`).
6.  **Persistent Private Key Access (Persistence)**: Despite the ownership transfer, the attacker, as the original `creator_id`, can still re-fetch the certificate's private key via the `/api/1/certificates/{id}/key` endpoint, due to the creator-equality IDOR vulnerability, granting them permanent access.

## Impact

Successful exploitation of this vulnerability chain leads to severe consequences. Attackers gain access to the AWS STS credentials of the Lemur worker role, potentially allowing them to compromise various AWS resources and services that the Lemur role has permissions to manage. Furthermore, the attacker achieves permanent access to any TLS private keys they issue through Lemur, regardless of subsequent ownership changes or auditing attempts. This undermines the integrity of the organization's Public Key Infrastructure (PKI), enabling decryption of sensitive communications, impersonation of services, or unauthorized signing. The persistent nature of the private key access means that even typical incident response actions like transferring certificate ownership will not revoke the attacker's access.

## Recommendation

*   **Patch Lemur immediately**: Upgrade `github.com/Netflix/lemur` to a version higher than 1.9.0 that contains fixes for these vulnerabilities. If a patch is not available, apply vendor-provided mitigations for CVE-918, CVE-639, and CVE-285.
*   **Review and Harden SSO Integration**: Configure Lemur's SSO integration to require administrative approval for new user accounts or implement allowlists for email domains, as highlighted by the `SSO auto-provision` vulnerability.
*   **Deploy Sigma Rule for SSRF**: Implement the `Detect Lemur ACME SSRF to IMDS` Sigma rule to detect attempts to configure ACME authorities with IMDS endpoints or other RFC1918 addresses.
*   **Deploy Sigma Rule for Private Key Exfiltration**: Implement the `Detect Lemur Certificate Private Key Exfiltration` Sigma rule to identify suspicious retrieval of certificate private keys by original creators after ownership transfer.
*   **Monitor Lemur API Logs**: Actively monitor API calls to `/api/1/authorities` for `acme_url` values pointing to internal IP addresses (e.g., `169.254.169.254`) or unexpected external hosts, and API calls to `/api/1/certificates/{id}/key` from users who are not the current `owner`.
