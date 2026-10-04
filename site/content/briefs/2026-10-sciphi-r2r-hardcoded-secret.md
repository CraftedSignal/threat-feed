---
title: Hard-coded JWT Secrets in SciPhi-AI R2R
slug: 2026-10-sciphi-r2r-hardcoded-secret
description: SciPhi-AI R2R versions up to 3.6.6 contain a vulnerability in the JWT Secret Handler component that uses hard-coded credentials, allowing remote attackers to bypass authentication.
date: "2026-10-04T14:52:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sciphi:r2r:*:*:*:*:*:*:*:*
vendors:
  - SciPhi-AI
products:
  - R2R (<= 3.6.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This manipulation of the argument DEFAULT_BCRYPT_SECRET_KEY/DEFAULT_NACL_SECRET_KEY causes hard-coded credentials.
    confidence_band: high
cves:
  - id: CVE-2026-105147
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105147
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Review R2R configuration files and replace hard-coded secret keys
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows authentication bypass using known keys
  mitigation_plan:
    - priority: immediate
      action: Restrict public access to R2R application instances
      owner: IT Operations
      addresses: CVE-2026-105147
      evidence: Publicly disclosed exploit available
---

SciPhi-AI R2R versions up to and including 3.6.6 contain a security vulnerability in the JWT Secret Handler component. The application improperly utilizes hard-coded credentials for DEFAULT_BCRYPT_SECRET_KEY and DEFAULT_NACL_SECRET_KEY, which are used to sign and verify JSON Web Tokens (JWT). An unauthenticated remote attacker can leverage these known, static values to forge authentication tokens, potentially leading to unauthorized access to the application and elevated privileges. The vulnerability has been publicly disclosed and is susceptible to exploitation, posing a significant risk to R2R deployments. As the vendor has not responded to disclosure attempts, no official patch is currently available, necessitating immediate mitigation through configuration hardening.

## Impact

The vulnerability allows unauthenticated remote attackers to bypass authentication mechanisms. If exploited, an attacker can gain administrative access to the R2R platform, leading to potential data exfiltration, unauthorized modification of configurations, or total compromise of the R2R instance. The scope of impact is limited to organizations running SciPhi-AI R2R versions up to 3.6.6 in internet-facing environments.

## Recommendation

- Identify all instances of SciPhi-AI R2R in the environment and ensure they are isolated from public network access.
- Review application configuration files for the presence of the default values for DEFAULT_BCRYPT_SECRET_KEY and DEFAULT_NACL_SECRET_KEY and rotate them to unique, cryptographically strong values.
- Implement network-level access control lists (ACLs) to restrict access to R2R administrative endpoints to known, trusted management subnets.
- Monitor logs for unusual authentication patterns or signs of credential stuffing and unauthorized token usage, specifically looking for tokens that appear to be signed using the default, hard-coded key values if they are publicly known.
