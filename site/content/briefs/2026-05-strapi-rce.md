---
title: Strapi Unauthenticated Account Takeover via Relational Filtering Vulnerability (CVE-2026-27886)
slug: 2026-05-strapi-rce
description: Strapi versions prior to 5.37.0 are vulnerable to an unauthenticated boolean-oracle attack against private fields on the joined `admin_users` table, including the `resetPasswordToken` field, via the 'where' query parameter on publicly accessible content-types; extracting an admin reset token via this oracle makes full administrative account takeover possible without authentication.
date: "2026-05-14T13:21:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - strapi
  - account takeover
  - vulnerability
vendors:
  - Strapi
products:
  - '@strapi/strapi'
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://github.com/advisories/GHSA-rjg2-95x7-8qmx
  - CVE-2026-27886
rules:
  - title: Detect Strapi resetPasswordToken Oracle Attempts (CVE-2026-27886)
    description: Detects CVE-2026-27886 exploitation — attempts to exploit the Strapi resetPasswordToken boolean oracle by monitoring for suspicious `where` query parameters in web server access logs.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1595.002
    data_sources:
      - webserver
  - title: Detect Strapi Admin Password Reset After Potential Exploitation (CVE-2026-27886)
    description: Detects CVE-2026-27886 exploitation — monitors for admin password resets immediately following suspicious requests with `where[updatedBy]` query parameters.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1595.002
    data_sources:
      - webserver
rules_count: 2
---

Strapi versions prior to 5.37.0 contain a critical vulnerability (CVE-2026-27886) that allows unauthenticated attackers to perform account takeover. The vulnerability stems from insufficient sanitization of query parameters when filtering content via relational fields. An attacker can exploit this flaw by crafting malicious `where` query parameters targeting publicly accessible content types with an `updatedBy` (or other admin-relation) field. This allows for a boolean-oracle attack against private fields in the joined `admin_users` table, specifically targeting the `resetPasswordToken` field. Successful extraction of an admin reset token enables complete administrative account takeover without requiring any prior authentication. The vulnerability affects `@strapi/strapi` versions <=5.36.1.

## Attack Chain

1. An unauthenticated attacker identifies a publicly accessible content-type endpoint in the Strapi application that includes a relational field to the `admin_users` table (e.g., `updatedBy`, `createdBy`, `publishedBy`).
2. The attacker crafts a malicious HTTP GET request to the identified endpoint, using the `where` query parameter to filter results based on a private field in the `admin_users` table, such as `resetPasswordToken`.
3. The attacker injects special characters and operators (e.g., `$startsWith`, `$contains`, `$eq`) into the `where` query parameter to construct a boolean-oracle attack. Example: `where[updatedBy][resetPasswordToken][$startsWith]=a`.
4. The vulnerable Strapi application executes a `LEFT JOIN` query against the `admin_users` table without proper sanitization, allowing the attacker to infer information about the `resetPasswordToken` field based on the response.
5. The attacker iterates through a hex alphabet (`0`-`9`, `a`-`f`) to progressively reveal the `resetPasswordToken` value one character at a time by observing subtle differences in the response.
6. Once the attacker has successfully extracted the complete `resetPasswordToken`, they make a `POST /admin/reset-password` request with the stolen token.
7. The Strapi application validates the stolen reset token, and allows the attacker to set a new password for the targeted administrator account.
8. The attacker successfully logs in to the Strapi admin panel using the newly set password, achieving full administrative account takeover.

## Impact

Successful exploitation of CVE-2026-27886 allows unauthenticated attackers to gain complete control over the Strapi application. This can lead to data breaches, unauthorized modifications, and denial of service. The affected versions are `@strapi/strapi` <=5.36.1. The impact is considered critical due to the ease of exploitation and the high level of access gained.

## Recommendation

*   Immediately upgrade your Strapi installation to version >=5.37.0 to patch CVE-2026-27886, as recommended in the advisory.
*   Deploy the Sigma rule "Detect Strapi resetPasswordToken Oracle Attempts (CVE-2026-27886)" to detect potential exploitation attempts by monitoring for suspicious `where` query parameters in web server access logs.
*   Deploy the Sigma rule "Detect Strapi Admin Password Reset After Potential Exploitation (CVE-2026-27886)" to detect potential exploitation attempts by monitoring for admin password resets following suspicious activity.
*   Monitor server access logs for query strings containing patterns matching `\?(.*&)?where\[(updatedBy|createdBy|publishedBy)\]\[(email|password|resetPasswordToken|confirmationToken|firstname|lastname|preferedLanguage)\]\[\$(startsWith|contains|eq|gt|lt|ge|le|in|notIn|notNull|null)\]=` as described in the advisory.
