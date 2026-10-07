---
title: Insecure Local TLS Private Key Storage in Quasar Framework
slug: 2026-10-quasar-ssl-vuln
description: The @quasar/ssl-certificate development utility caches TLS private keys with overly permissive filesystem permissions, enabling local unauthorized access and impersonation of development endpoints.
date: "2026-10-07T16:59:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - development-tooling
vendors:
  - Quasar
products:
  - '@quasar/ssl-certificate (<= 2.0.0)'
  - '@quasar/cli (<= 5.0.3)'
  - '@quasar/app-vite (<= 3.2.0)'
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A local attacker with filesystem access could copy and reuse the private key to impersonate a development TLS endpoint in an environment that trusts the certificate.
    confidence_band: high
cves:
  - id: CVE-2026-106105
references:
  - https://github.com/advisories/GHSA-fh39-c73x-5pjv
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-106105
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Update @quasar/ssl-certificate, @quasar/cli, and @quasar/app-vite to versions containing the fix for CVE-2026-106105.
      owner: IT Operations
      addresses: CVE-2026-106105
      evidence: The remediation writes and repairs the cached PEM with owner-only permissions.
---

The Quasar Framework development utility, specifically the @quasar/ssl-certificate package, contains a security vulnerability (CVE-2026-106105) related to how it handles cached development TLS private keys. When the utility generates and caches a combined PEM file containing a private key and its associated certificate, it fails to explicitly restrict filesystem permissions. Consequently, on many systems, the resulting file is readable by other local users depending on the system's umask settings.

Furthermore, the generated certificates were identified as having overly broad security parameters, including CA-capability and excessive key usage. An attacker with local filesystem access can read the cached private key and use it to impersonate a development TLS endpoint in environments where the certificate is trusted. This issue impacts several Quasar components, including the CLI and Vite application packages, which utilize this utility for local development environments. Remediation involves ensuring the cached PEM files are written with owner-only permissions and updating certificate generation logic to constrain key usage and remove CA-capability.

## Impact

Successful exploitation allows a local attacker to obtain a valid private TLS key used in development environments. This enables the attacker to perform machine-in-the-middle attacks or impersonate local development services that rely on these certificates for trust. This risk is primarily relevant in multi-user development environments, shared build servers, or local workstations where malicious actors have already established a foothold or have legitimate local access.

## Recommendation

Prioritize updating all instances of @quasar/ssl-certificate, @quasar/cli, and @quasar/app-vite to versions that address CVE-2026-106105. For environments where upgrades are delayed, implement strict local filesystem permission audits on development directories where Quasar projects reside.
