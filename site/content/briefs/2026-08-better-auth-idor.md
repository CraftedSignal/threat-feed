---
title: Insecure Direct Object Reference in better-auth passkey
slug: 2026-08-better-auth-idor
description: An Insecure Direct Object Reference (IDOR) vulnerability (CVE-2025-71400) in better-auth passkey versions before 1.4.0 allows authenticated users to delete arbitrary passkeys by enumerating IDs.
date: "2026-08-02T13:35:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - authentication
  - web-application
  - cve-2025-71400
vendors:
  - better-auth
products:
  - passkey (< 1.4.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: better-auth passkey versions before 1.4.0 contain an insecure direct object reference vulnerability in the passkey deletion endpoint that allows authenticated users to delete arbitrary passkeys by ID.
    confidence_band: high
cves:
  - id: CVE-2025-71400
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71400
  - https://github.com/better-auth/better-auth/security/advisories/GHSA-4vcf-q4xf-f48m
  - https://www.vulncheck.com/advisories/better-auth-passkey-before-idor-via-delete-passkey
rules:
  - title: Detect CVE-2025-71400 - Potential IDOR in better-auth passkey deletion
    description: Detects potential exploitation of CVE-2025-71400 by monitoring for high-frequency or anomalous access to the passkey deletion endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
---

better-auth passkey versions before 1.4.0 are affected by an Insecure Direct Object Reference (IDOR) vulnerability, tracked as CVE-2025-71400. The vulnerability resides in the passkey deletion endpoint, which fails to adequately verify that the authenticated user performing the deletion request is the owner of the requested passkey ID. By submitting crafted requests to the delete-passkey endpoint, an authenticated attacker can enumerate and delete passkeys belonging to other users, leading to unauthorized account access disruption or potential account recovery bypass scenarios. This vulnerability is classified as CWE-639 (Authorization Bypass Through User-Controlled Key) and requires an active session to exploit. Organizations using the better-auth framework for passkey management should prioritize upgrading to version 1.4.0 or later to remediate the authorization logic flaw.

## Attack Chain

1. Attacker establishes a valid user session within the application using the better-auth library.
2. Attacker performs discovery to identify the structure of the API request used for passkey management.
3. Attacker intercepts the legitimate 'delete-passkey' request using a proxy tool.
4. Attacker modifies the request parameters to iterate or guess passkey IDs that do not belong to the current user session.
5. Attacker submits the crafted HTTP request to the application server.
6. The vulnerable endpoint fails to validate authorization, processing the deletion request for the unauthorized resource.
7. The target user's passkey is successfully removed from the backend database.

## Impact

Successful exploitation allows authenticated attackers to perform unauthorized deletion of other users' passkeys. This can result in widespread denial of service for user authentication methods, forced account recovery workflows, and degradation of security posture for affected applications. The vulnerability affects all users leveraging the affected better-auth versions.

## Recommendation

1. Upgrade the better-auth package to version 1.4.0 or higher immediately to apply the fix for CVE-2025-71400.
2. Deploy web application firewall (WAF) or API gateway rules to monitor for unusual patterns of authorization failures or high-frequency deletion attempts targeting user-specific API endpoints.
3. Audit access logs for unauthorized access patterns where a single session identifier is linked to a high volume of deletion requests across disparate resource IDs.
