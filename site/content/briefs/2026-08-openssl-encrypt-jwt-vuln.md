---
title: Hardcoded JWT Signing Secrets in openssl_encrypt
slug: 2026-08-openssl-encrypt-jwt-vuln
description: The openssl_encrypt library versions before 1.4.0 contain hardcoded JWT signing secrets that allow for arbitrary token forgery and unauthorized API access.
date: "2026-08-17T12:50:36Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - openssl_encrypt (< 1.4.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: openssl_encrypt versions before 1.4.0 contain hardcoded default JWT signing secrets in config.py that pass validation checks.
    confidence_band: high
cves:
  - id: CVE-2026-74893
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74893
  - https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-qc6h-gfjh-7qqg
  - https://www.vulncheck.com/advisories/openssl-encrypt-before-jwt-token-forgery-via-hardcoded-secrets
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade openssl_encrypt to version 1.4.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-74893 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Rotate all JWT signing secrets used in production
      owner: Security Engineering
      addresses: CVE-2026-74893
      evidence: Hardcoded secret exposure requires credential rotation
---

The openssl_encrypt Python library, specifically versions prior to 1.4.0, contains hardcoded default JWT signing secrets within the 'config.py' file. This flaw allows attackers to derive the secret used for signing authentication tokens. By leveraging the known secret, an unauthorized actor can forge valid JWT tokens for any client_id. Successfully forging these tokens grants the attacker authenticated access to sensitive backend services, including keyserver and telemetry APIs, bypassing standard identity and access management controls. This vulnerability (CVE-2026-74893) is classified as a 'Use of Hard-coded Credentials' (CWE-798) and requires immediate remediation by upgrading to version 1.4.0 or higher.

## Impact

The vulnerability poses a high risk to systems utilizing openssl_encrypt for authentication or telemetry data processing. Unauthorized access via forged tokens could result in the exfiltration of sensitive telemetry data, compromise of cryptographic keys handled by the keyserver API, and full identity impersonation within the application environment.

## Recommendation

- Upgrade the 'openssl_encrypt' package to version 1.4.0 or later immediately to remove the hardcoded secret.
- Review all JWT tokens issued or validated by applications using 'openssl_encrypt' prior to the upgrade for signs of suspicious or unauthorized client_id generation.
- Rotate all secrets and cryptographic material associated with the affected keyserver and telemetry APIs if there is evidence that the hardcoded secret was exposed or exploited.
